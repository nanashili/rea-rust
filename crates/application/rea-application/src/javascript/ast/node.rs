//! Babel-shaped node views over the oxc AST.
//!
//! A [`Node`] is one node as Babel's `@babel/parser` (8.x, default options,
//! `createParenthesizedExpressions: false`) would produce it for the same
//! source: its Babel type name, its Babel `start`/`end` (as a UTF-8 byte
//! [`Span`]; convert with [`super::AstContext`]), its `extra.parenthesized`
//! flag, and a stable [`NodeKey`] for side tables. Children come from
//! [`Node::children`] in `t.VISITOR_KEYS` order.
//!
//! The vocabulary differences are owned here, once:
//!
//! - Optional chains: oxc's `ChainExpression` has no Babel node. Each member,
//!   call and `TSNonNullExpression` on the chain spine carries the number of
//!   optional links at or below it (`chain`); a member/call is
//!   `Optional*Expression` iff that number is positive, as in Babel, where
//!   links above the first `?.` keep `optional: false` but stay `Optional*`.
//! - `ObjectMethod`/`ClassMethod`/`ClassPrivateMethod`/`TSDeclareMethod` are
//!   the oxc property/method with its `Function` value folded in. The method
//!   view owns the callable identity; its key is the property/method node.
//! - Patterns vs assignment targets: binding patterns (`BindingPattern`) and
//!   write targets (`AssignmentTarget*`) are distinct oxc families that map to
//!   the same Babel pattern names, with separate views.
//! - Parameters: the TS `this` parameter (`Function.this_param`) is Babel
//!   `params[0]`, an `Identifier` named `this`; a defaulted parameter is an
//!   `AssignmentPattern`; accessibility/readonly/override parameters are
//!   `TSParameterProperty`; the rest parameter is a `RestElement` that owns its
//!   type annotation. Type annotations of identifiers and object/array
//!   patterns extend the Babel node's span, as Babel does.
//! - Parentheses: `ParenthesizedExpression`/`TSParenthesizedType` are
//!   transparent (never a node, never counted toward depth or order); the
//!   innermost node records `parenthesized`.
//! - Babel 8 shapes: `export * as ns` is an `ExportNamedDeclaration` with an
//!   `ExportNamespaceSpecifier`; dotted `namespace A.B` is one
//!   `TSModuleDeclaration` with a `TSQualifiedName` id; `declare global` is a
//!   `TSModuleDeclaration` with an `Identifier` id; directives are
//!   `Directive` + `DirectiveLiteral`; private names are `PrivateName` with an
//!   inner `Identifier`.
//!
//! Babel-only nodes with no oxc input (`Import` callee, `ArgumentPlaceholder`,
//! `TypeCastExpression`, `ExportDefaultSpecifier`, Flow) have no view.

use oxc_ast::ast::*;
use oxc_semantic::NodeId;
use oxc_span::{GetSpan, Span};

/// Identity of one Babel view: the backing oxc node plus a role that
/// separates distinct Babel nodes synthesized from the same oxc node (for
/// example a `PrivateName` and its inner `Identifier`). Spans are not unique
/// (a wrapper and its inner node can share one), so side tables key on this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeKey {
    pub node: NodeId,
    pub role: Role,
}

/// Which Babel view of an oxc node a [`NodeKey`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// The view that corresponds to the oxc node itself.
    Primary,
    /// A second Babel node synthesized from the same oxc node.
    Synthesized,
}

/// One Babel-shaped node.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    kind: NodeKind<'a>,
    span: Span,
    key: NodeKey,
    parenthesized: bool,
}

/// The oxc data behind a [`Node`]. Variants are named after the Babel node
/// they produce, or after the oxc node where one variant yields several
/// Babel types (see [`Node::babel_type`]).
#[derive(Clone, Copy, Debug)]
pub enum NodeKind<'a> {
    Program(&'a Program<'a>),
    Directive(&'a Directive<'a>),
    DirectiveLiteral(&'a StringLiteral<'a>),
    /// A function body, as Babel `BlockStatement`.
    FunctionBody(&'a FunctionBody<'a>),
    BlockStatement(&'a BlockStatement<'a>),
    StaticBlock(&'a StaticBlock<'a>),
    EmptyStatement(&'a EmptyStatement),
    DebuggerStatement(&'a DebuggerStatement),
    ExpressionStatement(&'a ExpressionStatement<'a>),
    IfStatement(&'a IfStatement<'a>),
    DoWhileStatement(&'a DoWhileStatement<'a>),
    WhileStatement(&'a WhileStatement<'a>),
    ForStatement(&'a ForStatement<'a>),
    ForInStatement(&'a ForInStatement<'a>),
    ForOfStatement(&'a ForOfStatement<'a>),
    ContinueStatement(&'a ContinueStatement<'a>),
    BreakStatement(&'a BreakStatement<'a>),
    ReturnStatement(&'a ReturnStatement<'a>),
    WithStatement(&'a WithStatement<'a>),
    SwitchStatement(&'a SwitchStatement<'a>),
    SwitchCase(&'a SwitchCase<'a>),
    LabeledStatement(&'a LabeledStatement<'a>),
    ThrowStatement(&'a ThrowStatement<'a>),
    TryStatement(&'a TryStatement<'a>),
    CatchClause(&'a CatchClause<'a>),
    VariableDeclaration(&'a VariableDeclaration<'a>),
    VariableDeclarator(&'a VariableDeclarator<'a>),

    // Identifiers.
    IdentifierName(&'a IdentifierName<'a>),
    IdentifierReference(&'a IdentifierReference<'a>),
    LabelIdentifier(&'a LabelIdentifier<'a>),
    /// A binding identifier with the type annotation and decorators Babel
    /// attaches to it.
    BindingIdentifier {
        id: &'a BindingIdentifier<'a>,
        annotation: Option<&'a TSTypeAnnotation<'a>>,
        decorators: &'a [Decorator<'a>],
    },
    /// The TS `this` parameter, as Babel `Identifier` `this`.
    ThisParameter(&'a TSThisParameter<'a>),
    /// A TS index-signature parameter, as Babel `Identifier`.
    IndexSignatureName(&'a TSIndexSignatureName<'a>),
    /// The key of a shorthand assignment-target property (`{a} = o`); the
    /// value is the same oxc identifier as a separate Babel node.
    ShorthandTargetKey(&'a IdentifierReference<'a>),
    PrivateName(&'a PrivateIdentifier<'a>),
    /// The `Identifier` inside a `PrivateName` (span without `#`).
    PrivateNameId(&'a PrivateIdentifier<'a>),

    // Literals.
    BooleanLiteral(&'a BooleanLiteral),
    NullLiteral(&'a NullLiteral),
    NumericLiteral(&'a NumericLiteral<'a>),
    BigIntLiteral(&'a BigIntLiteral<'a>),
    RegExpLiteral(&'a RegExpLiteral<'a>),
    StringLiteral(&'a StringLiteral<'a>),
    TemplateLiteral(&'a TemplateLiteral<'a>),
    TemplateElement(&'a TemplateElement<'a>),

    // Expressions.
    ThisExpression(&'a ThisExpression),
    Super(&'a Super),
    ArrayExpression(&'a ArrayExpression<'a>),
    ObjectExpression(&'a ObjectExpression<'a>),
    /// `ObjectProperty` (plain or shorthand).
    ObjectProperty(&'a ObjectProperty<'a>),
    /// `ObjectMethod` (method, getter or setter): the property with its function.
    ObjectMethod(&'a ObjectProperty<'a>),
    SpreadElement(&'a SpreadElement<'a>),
    TaggedTemplateExpression(&'a TaggedTemplateExpression<'a>),
    /// `MemberExpression` or `OptionalMemberExpression` (`chain > 0`).
    Member {
        member: &'a MemberExpression<'a>,
        chain: u32,
    },
    /// `CallExpression` or `OptionalCallExpression` (`chain > 0`).
    Call {
        call: &'a CallExpression<'a>,
        chain: u32,
    },
    NewExpression(&'a NewExpression<'a>),
    ImportExpression(&'a ImportExpression<'a>),
    MetaProperty(&'a MetaProperty<'a>),
    UpdateExpression(&'a UpdateExpression<'a>),
    UnaryExpression(&'a UnaryExpression<'a>),
    BinaryExpression(&'a BinaryExpression<'a>),
    /// `#x in o`, as Babel `BinaryExpression` with a `PrivateName` left.
    PrivateInExpression(&'a PrivateInExpression<'a>),
    LogicalExpression(&'a LogicalExpression<'a>),
    ConditionalExpression(&'a ConditionalExpression<'a>),
    AssignmentExpression(&'a AssignmentExpression<'a>),
    SequenceExpression(&'a SequenceExpression<'a>),
    AwaitExpression(&'a AwaitExpression<'a>),
    YieldExpression(&'a YieldExpression<'a>),
    V8IntrinsicExpression(&'a V8IntrinsicExpression<'a>),

    // Functions and classes.
    /// `FunctionDeclaration`, `FunctionExpression` or `TSDeclareFunction`.
    Function(&'a Function<'a>),
    ArrowFunctionExpression(&'a ArrowFunctionExpression<'a>),
    /// `ClassDeclaration` or `ClassExpression`.
    Class(&'a Class<'a>),
    ClassBody(&'a ClassBody<'a>),
    /// `ClassMethod`, `ClassPrivateMethod` or `TSDeclareMethod`.
    ClassMethod(&'a MethodDefinition<'a>),
    /// `ClassProperty` or `ClassPrivateProperty`.
    ClassProperty(&'a PropertyDefinition<'a>),
    ClassAccessorProperty(&'a AccessorProperty<'a>),
    Decorator(&'a Decorator<'a>),

    // Binding patterns.
    ObjectPattern {
        pattern: &'a ObjectPattern<'a>,
        annotation: Option<&'a TSTypeAnnotation<'a>>,
        decorators: &'a [Decorator<'a>],
    },
    ArrayPattern {
        pattern: &'a ArrayPattern<'a>,
        annotation: Option<&'a TSTypeAnnotation<'a>>,
    },
    AssignmentPattern(&'a AssignmentPattern<'a>),
    /// A binding-pattern property, as Babel `ObjectProperty`.
    BindingProperty(&'a BindingProperty<'a>),
    /// A rest element inside a binding pattern.
    BindingRestElement(&'a BindingRestElement<'a>),
    /// A rest parameter, as Babel `RestElement` owning its annotation.
    RestParameter(&'a FormalParameterRest<'a>),
    /// A parameter with a default, as Babel `AssignmentPattern`.
    DefaultParameter(&'a FormalParameter<'a>),
    /// A parameter with accessibility/readonly/override, as `TSParameterProperty`.
    ParameterProperty(&'a FormalParameter<'a>),

    // Assignment targets.
    ArrayAssignmentTarget(&'a ArrayAssignmentTarget<'a>),
    ObjectAssignmentTarget(&'a ObjectAssignmentTarget<'a>),
    AssignmentTargetRest(&'a AssignmentTargetRest<'a>),
    AssignmentTargetWithDefault(&'a AssignmentTargetWithDefault<'a>),
    /// Shorthand target property `{a}` / `{a = 1}`, as Babel `ObjectProperty`.
    AssignmentTargetPropertyIdentifier(&'a AssignmentTargetPropertyIdentifier<'a>),
    /// The `a = 1` value of a shorthand target property, as `AssignmentPattern`.
    ShorthandTargetDefault(&'a AssignmentTargetPropertyIdentifier<'a>),
    AssignmentTargetPropertyProperty(&'a AssignmentTargetPropertyProperty<'a>),

    // Modules.
    ImportDeclaration(&'a ImportDeclaration<'a>),
    ImportSpecifier(&'a ImportSpecifier<'a>),
    ImportDefaultSpecifier(&'a ImportDefaultSpecifier<'a>),
    ImportNamespaceSpecifier(&'a ImportNamespaceSpecifier<'a>),
    ImportAttribute(&'a ImportAttribute<'a>),
    ExportNamedDeclaration(&'a ExportNamedDeclaration<'a>),
    ExportDefaultDeclaration(&'a ExportDefaultDeclaration<'a>),
    /// `ExportAllDeclaration`, or `ExportNamedDeclaration` when it has
    /// `exported` (Babel 8 `export * as ns`).
    ExportAllDeclaration(&'a ExportAllDeclaration<'a>),
    /// The `* as ns` of an `export * as ns from`.
    ExportNamespaceSpecifier(&'a ExportAllDeclaration<'a>),
    ExportSpecifier(&'a ExportSpecifier<'a>),

    // JSX.
    JSXElement(&'a JSXElement<'a>),
    JSXOpeningElement(&'a JSXOpeningElement<'a>),
    JSXClosingElement(&'a JSXClosingElement<'a>),
    JSXFragment(&'a JSXFragment<'a>),
    JSXOpeningFragment(&'a JSXOpeningFragment),
    JSXClosingFragment(&'a JSXClosingFragment),
    JSXNamespacedName(&'a JSXNamespacedName<'a>),
    JSXMemberExpression(&'a JSXMemberExpression<'a>),
    JSXExpressionContainer(&'a JSXExpressionContainer<'a>),
    JSXEmptyExpression(&'a JSXEmptyExpression),
    JSXAttribute(&'a JSXAttribute<'a>),
    JSXSpreadAttribute(&'a JSXSpreadAttribute<'a>),
    JSXIdentifier(&'a JSXIdentifier<'a>),
    /// A JSX tag name parsed as an identifier reference (`<Foo>`).
    JSXIdentifierReference(&'a IdentifierReference<'a>),
    /// `this` as a JSX tag name or member object.
    JSXThis(&'a ThisExpression),
    JSXSpreadChild(&'a JSXSpreadChild<'a>),
    JSXText(&'a JSXText<'a>),

    // TypeScript.
    TSAsExpression(&'a TSAsExpression<'a>),
    TSSatisfiesExpression(&'a TSSatisfiesExpression<'a>),
    TSTypeAssertion(&'a TSTypeAssertion<'a>),
    TSNonNullExpression {
        expression: &'a TSNonNullExpression<'a>,
        chain: u32,
    },
    TSInstantiationExpression(&'a TSInstantiationExpression<'a>),
    TSTypeAnnotation(&'a TSTypeAnnotation<'a>),
    TSTypeParameterDeclaration(&'a TSTypeParameterDeclaration<'a>),
    TSTypeParameter(&'a TSTypeParameter<'a>),
    TSTypeParameterInstantiation(&'a TSTypeParameterInstantiation<'a>),
    TSTypeAliasDeclaration(&'a TSTypeAliasDeclaration<'a>),
    TSInterfaceDeclaration(&'a TSInterfaceDeclaration<'a>),
    TSInterfaceBody(&'a TSInterfaceBody<'a>),
    TSInterfaceHeritage(&'a TSInterfaceHeritage<'a>),
    TSClassImplements(&'a TSClassImplements<'a>),
    TSPropertySignature(&'a TSPropertySignature<'a>),
    TSMethodSignature(&'a TSMethodSignature<'a>),
    TSCallSignatureDeclaration(&'a TSCallSignatureDeclaration<'a>),
    TSConstructSignatureDeclaration(&'a TSConstructSignatureDeclaration<'a>),
    TSIndexSignature(&'a TSIndexSignature<'a>),
    TSEnumDeclaration(&'a TSEnumDeclaration<'a>),
    TSEnumBody(&'a TSEnumBody<'a>),
    TSEnumMember(&'a TSEnumMember<'a>),
    /// The outermost declaration of a (possibly dotted) `TSModuleDeclaration`.
    TSModuleDeclaration(&'a TSModuleDeclaration<'a>),
    /// `outer.a.b`: the `TSQualifiedName` of a dotted module name, ending at
    /// segment `depth` (>= 1) below `outer`.
    TSModuleQualifiedName {
        outer: &'a TSModuleDeclaration<'a>,
        depth: u32,
    },
    /// `declare global {}`, as Babel `TSModuleDeclaration`.
    TSGlobalDeclaration(&'a TSGlobalDeclaration<'a>),
    /// The `global` name of a `declare global`, as Babel `Identifier`.
    TSGlobalName(&'a TSGlobalDeclaration<'a>),
    TSModuleBlock(&'a TSModuleBlock<'a>),
    /// A string statement at the top of a namespace body: oxc parses a
    /// directive, Babel an `ExpressionStatement`.
    ModuleBlockDirective(&'a Directive<'a>),
    TSImportEqualsDeclaration(&'a TSImportEqualsDeclaration<'a>),
    TSExternalModuleReference(&'a TSExternalModuleReference<'a>),
    TSExportAssignment(&'a TSExportAssignment<'a>),
    TSNamespaceExportDeclaration(&'a TSNamespaceExportDeclaration<'a>),
    TSQualifiedName(&'a TSQualifiedName<'a>),
    /// A qualified `implements` name, which Babel 8 parses as `MemberExpression`.
    TSQualifiedNameMember(&'a TSQualifiedName<'a>),
    /// A qualified `import("x").A.B` qualifier, as Babel `TSQualifiedName`.
    TSImportTypeQualifiedName(&'a TSImportTypeQualifiedName<'a>),
    TSTypeReference(&'a TSTypeReference<'a>),
    TSTypeQuery(&'a TSTypeQuery<'a>),
    TSImportType(&'a TSImportType<'a>),
    TSFunctionType(&'a TSFunctionType<'a>),
    TSConstructorType(&'a TSConstructorType<'a>),
    TSTypePredicate(&'a TSTypePredicate<'a>),
    TSTypeLiteral(&'a TSTypeLiteral<'a>),
    TSArrayType(&'a TSArrayType<'a>),
    TSTupleType(&'a TSTupleType<'a>),
    TSNamedTupleMember(&'a TSNamedTupleMember<'a>),
    TSOptionalType(&'a TSOptionalType<'a>),
    TSRestType(&'a TSRestType<'a>),
    TSUnionType(&'a TSUnionType<'a>),
    TSIntersectionType(&'a TSIntersectionType<'a>),
    TSConditionalType(&'a TSConditionalType<'a>),
    TSInferType(&'a TSInferType<'a>),
    TSTypeOperator(&'a TSTypeOperator<'a>),
    TSIndexedAccessType(&'a TSIndexedAccessType<'a>),
    TSMappedType(&'a TSMappedType<'a>),
    TSTemplateLiteralType(&'a TSTemplateLiteralType<'a>),
    TSLiteralType(&'a TSLiteralType<'a>),
    TSThisType(&'a TSThisType),
    /// A TS keyword type; the payload is its Babel type name.
    TSKeyword(&'static str),
    /// A JSDoc type (`?T`, `T!`, `?`); Babel's TypeScript plugin has no such
    /// node, so it only appears in recovered sources. Payload: oxc name.
    JSDocType(&'static str),
}

impl<'a> Node<'a> {
    pub(super) fn new(kind: NodeKind<'a>, span: Span, node: NodeId) -> Self {
        Self {
            kind,
            span,
            key: NodeKey {
                node,
                role: Role::Primary,
            },
            parenthesized: false,
        }
    }

    pub(super) fn synthesized(kind: NodeKind<'a>, span: Span, node: NodeId) -> Self {
        Self {
            kind,
            span,
            key: NodeKey {
                node,
                role: Role::Synthesized,
            },
            parenthesized: false,
        }
    }

    pub(super) fn with_span(mut self, span: Span) -> Self {
        self.span = span;
        self
    }

    pub(super) fn with_parenthesized(mut self, parenthesized: bool) -> Self {
        self.parenthesized = parenthesized;
        self
    }

    /// The oxc data behind this view.
    pub fn kind(&self) -> NodeKind<'a> {
        self.kind
    }

    /// Babel `start`/`end` as a UTF-8 byte span. Convert through
    /// [`super::AstContext`] before emitting or keying on positions.
    pub fn span(&self) -> Span {
        self.span
    }

    /// Side-table identity.
    pub fn key(&self) -> NodeKey {
        self.key
    }

    /// Babel `extra.parenthesized`: the source wrapped this node in at least
    /// one pair of parentheses (expressions and TS types only).
    pub fn parenthesized(&self) -> bool {
        self.parenthesized
    }

    /// Babel's `Expression` alias over the supported node vocabulary.
    ///
    /// An oxc expression can also represent `Super` or a V8 intrinsic name;
    /// Babel does not admit those as ordinary expression-valued arguments.
    pub fn is_expression(&self) -> bool {
        matches!(
            self.babel_type(),
            "ArrayExpression"
                | "AssignmentExpression"
                | "BinaryExpression"
                | "CallExpression"
                | "ConditionalExpression"
                | "FunctionExpression"
                | "Identifier"
                | "StringLiteral"
                | "NumericLiteral"
                | "NullLiteral"
                | "BooleanLiteral"
                | "RegExpLiteral"
                | "LogicalExpression"
                | "MemberExpression"
                | "NewExpression"
                | "ObjectExpression"
                | "SequenceExpression"
                | "ThisExpression"
                | "UnaryExpression"
                | "UpdateExpression"
                | "ArrowFunctionExpression"
                | "ClassExpression"
                | "MetaProperty"
                | "TaggedTemplateExpression"
                | "TemplateLiteral"
                | "YieldExpression"
                | "AwaitExpression"
                | "ImportExpression"
                | "BigIntLiteral"
                | "OptionalMemberExpression"
                | "OptionalCallExpression"
                | "JSXElement"
                | "JSXFragment"
                | "TSInstantiationExpression"
                | "TSAsExpression"
                | "TSSatisfiesExpression"
                | "TSTypeAssertion"
                | "TSNonNullExpression"
        )
    }

    /// Babel `node.type`. Also the token name fingerprints hash
    /// (`babel-ast-v3`); see `docs` in the module header for the mapping.
    pub fn babel_type(&self) -> &'static str {
        use NodeKind as K;
        match self.kind {
            K::Program(_) => "Program",
            K::Directive(_) => "Directive",
            K::DirectiveLiteral(_) => "DirectiveLiteral",
            K::FunctionBody(_) | K::BlockStatement(_) => "BlockStatement",
            K::StaticBlock(_) => "StaticBlock",
            K::EmptyStatement(_) => "EmptyStatement",
            K::DebuggerStatement(_) => "DebuggerStatement",
            K::ExpressionStatement(_) => "ExpressionStatement",
            K::IfStatement(_) => "IfStatement",
            K::DoWhileStatement(_) => "DoWhileStatement",
            K::WhileStatement(_) => "WhileStatement",
            K::ForStatement(_) => "ForStatement",
            K::ForInStatement(_) => "ForInStatement",
            K::ForOfStatement(_) => "ForOfStatement",
            K::ContinueStatement(_) => "ContinueStatement",
            K::BreakStatement(_) => "BreakStatement",
            K::ReturnStatement(_) => "ReturnStatement",
            K::WithStatement(_) => "WithStatement",
            K::SwitchStatement(_) => "SwitchStatement",
            K::SwitchCase(_) => "SwitchCase",
            K::LabeledStatement(_) => "LabeledStatement",
            K::ThrowStatement(_) => "ThrowStatement",
            K::TryStatement(_) => "TryStatement",
            K::CatchClause(_) => "CatchClause",
            K::VariableDeclaration(_) => "VariableDeclaration",
            K::VariableDeclarator(_) => "VariableDeclarator",
            K::IdentifierName(_)
            | K::IdentifierReference(_)
            | K::LabelIdentifier(_)
            | K::BindingIdentifier { .. }
            | K::ThisParameter(_)
            | K::IndexSignatureName(_)
            | K::ShorthandTargetKey(_)
            | K::PrivateNameId(_)
            | K::TSGlobalName(_) => "Identifier",
            K::PrivateName(_) => "PrivateName",
            K::BooleanLiteral(_) => "BooleanLiteral",
            K::NullLiteral(_) => "NullLiteral",
            K::NumericLiteral(_) => "NumericLiteral",
            K::BigIntLiteral(_) => "BigIntLiteral",
            K::RegExpLiteral(_) => "RegExpLiteral",
            K::StringLiteral(_) => "StringLiteral",
            K::TemplateLiteral(_) => "TemplateLiteral",
            K::TemplateElement(_) => "TemplateElement",
            K::ThisExpression(_) => "ThisExpression",
            K::Super(_) => "Super",
            K::ArrayExpression(_) => "ArrayExpression",
            K::ObjectExpression(_) => "ObjectExpression",
            K::ObjectProperty(_)
            | K::BindingProperty(_)
            | K::AssignmentTargetPropertyIdentifier(_)
            | K::AssignmentTargetPropertyProperty(_) => "ObjectProperty",
            K::ObjectMethod(_) => "ObjectMethod",
            K::SpreadElement(_) => "SpreadElement",
            K::TaggedTemplateExpression(_) => "TaggedTemplateExpression",
            K::Member { chain, .. } => {
                if chain > 0 {
                    "OptionalMemberExpression"
                } else {
                    "MemberExpression"
                }
            }
            K::Call { chain, .. } => {
                if chain > 0 {
                    "OptionalCallExpression"
                } else {
                    "CallExpression"
                }
            }
            K::NewExpression(_) => "NewExpression",
            K::ImportExpression(_) => "ImportExpression",
            K::MetaProperty(_) => "MetaProperty",
            K::UpdateExpression(_) => "UpdateExpression",
            K::UnaryExpression(_) => "UnaryExpression",
            K::BinaryExpression(_) | K::PrivateInExpression(_) => "BinaryExpression",
            K::LogicalExpression(_) => "LogicalExpression",
            K::ConditionalExpression(_) => "ConditionalExpression",
            K::AssignmentExpression(_) => "AssignmentExpression",
            K::SequenceExpression(_) => "SequenceExpression",
            K::AwaitExpression(_) => "AwaitExpression",
            K::YieldExpression(_) => "YieldExpression",
            K::V8IntrinsicExpression(_) => "V8IntrinsicExpression",
            K::Function(function) => match function.r#type {
                _ if function.body.is_none() => "TSDeclareFunction",
                FunctionType::FunctionDeclaration => "FunctionDeclaration",
                FunctionType::TSDeclareFunction => "TSDeclareFunction",
                FunctionType::FunctionExpression | FunctionType::TSEmptyBodyFunctionExpression => {
                    "FunctionExpression"
                }
            },
            K::ArrowFunctionExpression(_) => "ArrowFunctionExpression",
            K::Class(class) => match class.r#type {
                ClassType::ClassDeclaration => "ClassDeclaration",
                ClassType::ClassExpression => "ClassExpression",
            },
            K::ClassBody(_) => "ClassBody",
            K::ClassMethod(method) => {
                if method.value.body.is_none() {
                    "TSDeclareMethod"
                } else if matches!(method.key, PropertyKey::PrivateIdentifier(_)) {
                    "ClassPrivateMethod"
                } else {
                    "ClassMethod"
                }
            }
            K::ClassProperty(property) => {
                if matches!(property.key, PropertyKey::PrivateIdentifier(_)) {
                    "ClassPrivateProperty"
                } else {
                    "ClassProperty"
                }
            }
            K::ClassAccessorProperty(_) => "ClassAccessorProperty",
            K::Decorator(_) => "Decorator",
            K::ObjectPattern { .. } | K::ObjectAssignmentTarget(_) => "ObjectPattern",
            K::ArrayPattern { .. } | K::ArrayAssignmentTarget(_) => "ArrayPattern",
            K::AssignmentPattern(_)
            | K::DefaultParameter(_)
            | K::AssignmentTargetWithDefault(_)
            | K::ShorthandTargetDefault(_) => "AssignmentPattern",
            K::BindingRestElement(_) | K::RestParameter(_) | K::AssignmentTargetRest(_) => {
                "RestElement"
            }
            K::ParameterProperty(_) => "TSParameterProperty",
            K::ImportDeclaration(_) => "ImportDeclaration",
            K::ImportSpecifier(_) => "ImportSpecifier",
            K::ImportDefaultSpecifier(_) => "ImportDefaultSpecifier",
            K::ImportNamespaceSpecifier(_) => "ImportNamespaceSpecifier",
            K::ImportAttribute(_) => "ImportAttribute",
            K::ExportNamedDeclaration(_) => "ExportNamedDeclaration",
            K::ExportDefaultDeclaration(_) => "ExportDefaultDeclaration",
            K::ExportAllDeclaration(declaration) => {
                if declaration.exported.is_some() {
                    "ExportNamedDeclaration"
                } else {
                    "ExportAllDeclaration"
                }
            }
            K::ExportNamespaceSpecifier(_) => "ExportNamespaceSpecifier",
            K::ExportSpecifier(_) => "ExportSpecifier",
            K::JSXElement(_) => "JSXElement",
            K::JSXOpeningElement(_) => "JSXOpeningElement",
            K::JSXClosingElement(_) => "JSXClosingElement",
            K::JSXFragment(_) => "JSXFragment",
            K::JSXOpeningFragment(_) => "JSXOpeningFragment",
            K::JSXClosingFragment(_) => "JSXClosingFragment",
            K::JSXNamespacedName(_) => "JSXNamespacedName",
            K::JSXMemberExpression(_) => "JSXMemberExpression",
            K::JSXExpressionContainer(_) => "JSXExpressionContainer",
            K::JSXEmptyExpression(_) => "JSXEmptyExpression",
            K::JSXAttribute(_) => "JSXAttribute",
            K::JSXSpreadAttribute(_) => "JSXSpreadAttribute",
            K::JSXIdentifier(_) | K::JSXIdentifierReference(_) | K::JSXThis(_) => "JSXIdentifier",
            K::JSXSpreadChild(_) => "JSXSpreadChild",
            K::JSXText(_) => "JSXText",
            K::TSAsExpression(_) => "TSAsExpression",
            K::TSSatisfiesExpression(_) => "TSSatisfiesExpression",
            K::TSTypeAssertion(_) => "TSTypeAssertion",
            K::TSNonNullExpression { .. } => "TSNonNullExpression",
            K::TSInstantiationExpression(_) => "TSInstantiationExpression",
            K::TSTypeAnnotation(_) => "TSTypeAnnotation",
            K::TSTypeParameterDeclaration(_) => "TSTypeParameterDeclaration",
            K::TSTypeParameter(_) => "TSTypeParameter",
            K::TSTypeParameterInstantiation(_) => "TSTypeParameterInstantiation",
            K::TSTypeAliasDeclaration(_) => "TSTypeAliasDeclaration",
            K::TSInterfaceDeclaration(_) => "TSInterfaceDeclaration",
            K::TSInterfaceBody(_) => "TSInterfaceBody",
            K::TSInterfaceHeritage(_) => "TSInterfaceHeritage",
            K::TSClassImplements(_) => "TSClassImplements",
            K::TSPropertySignature(_) => "TSPropertySignature",
            K::TSMethodSignature(_) => "TSMethodSignature",
            K::TSCallSignatureDeclaration(_) => "TSCallSignatureDeclaration",
            K::TSConstructSignatureDeclaration(_) => "TSConstructSignatureDeclaration",
            K::TSIndexSignature(_) => "TSIndexSignature",
            K::TSEnumDeclaration(_) => "TSEnumDeclaration",
            K::TSEnumBody(_) => "TSEnumBody",
            K::TSEnumMember(_) => "TSEnumMember",
            K::TSModuleDeclaration(_) | K::TSGlobalDeclaration(_) => "TSModuleDeclaration",
            K::TSModuleQualifiedName { .. }
            | K::TSQualifiedName(_)
            | K::TSImportTypeQualifiedName(_) => "TSQualifiedName",
            K::TSModuleBlock(_) => "TSModuleBlock",
            K::ModuleBlockDirective(_) => "ExpressionStatement",
            K::TSQualifiedNameMember(_) => "MemberExpression",
            K::TSImportEqualsDeclaration(_) => "TSImportEqualsDeclaration",
            K::TSExternalModuleReference(_) => "TSExternalModuleReference",
            K::TSExportAssignment(_) => "TSExportAssignment",
            K::TSNamespaceExportDeclaration(_) => "TSNamespaceExportDeclaration",
            K::TSTypeReference(_) => "TSTypeReference",
            K::TSTypeQuery(_) => "TSTypeQuery",
            K::TSImportType(_) => "TSImportType",
            K::TSFunctionType(_) => "TSFunctionType",
            K::TSConstructorType(_) => "TSConstructorType",
            K::TSTypePredicate(_) => "TSTypePredicate",
            K::TSTypeLiteral(_) => "TSTypeLiteral",
            K::TSArrayType(_) => "TSArrayType",
            K::TSTupleType(_) => "TSTupleType",
            K::TSNamedTupleMember(_) => "TSNamedTupleMember",
            K::TSOptionalType(_) => "TSOptionalType",
            K::TSRestType(_) => "TSRestType",
            K::TSUnionType(_) => "TSUnionType",
            K::TSIntersectionType(_) => "TSIntersectionType",
            K::TSConditionalType(_) => "TSConditionalType",
            K::TSInferType(_) => "TSInferType",
            K::TSTypeOperator(_) => "TSTypeOperator",
            K::TSIndexedAccessType(_) => "TSIndexedAccessType",
            K::TSMappedType(_) => "TSMappedType",
            K::TSTemplateLiteralType(_) => "TSTemplateLiteralType",
            K::TSLiteralType(_) => "TSLiteralType",
            K::TSThisType(_) => "TSThisType",
            K::TSKeyword(name) | K::JSDocType(name) => name,
        }
    }

    /// The function a callable view owns (`ObjectMethod`, class methods,
    /// functions); `None` for arrows and non-callables.
    pub fn function(&self) -> Option<&'a Function<'a>> {
        match self.kind {
            NodeKind::Function(function) => Some(function),
            NodeKind::ObjectMethod(property) => match &property.value {
                Expression::FunctionExpression(function) => Some(function),
                _ => None,
            },
            NodeKind::ClassMethod(method) => Some(&method.value),
            _ => None,
        }
    }
}

/// The Babel view of an expression: parentheses unwrapped (recorded as
/// `parenthesized`), chains resolved to `Optional*` links.
pub fn expression<'a>(mut expression: &'a Expression<'a>) -> Node<'a> {
    let mut parenthesized = false;
    while let Expression::ParenthesizedExpression(inner) = expression {
        parenthesized = true;
        expression = &inner.expression;
    }
    unparenthesized_expression(expression).with_parenthesized(parenthesized)
}

fn unparenthesized_expression<'a>(value: &'a Expression<'a>) -> Node<'a> {
    use NodeKind as K;
    macro_rules! node {
        ($variant:ident, $value:expr) => {{
            let value = &**$value;
            Node::new(K::$variant(value), value.span, value.node_id())
        }};
    }
    match value {
        Expression::BooleanLiteral(it) => node!(BooleanLiteral, it),
        Expression::NullLiteral(it) => node!(NullLiteral, it),
        Expression::NumericLiteral(it) => node!(NumericLiteral, it),
        Expression::BigIntLiteral(it) => node!(BigIntLiteral, it),
        Expression::RegExpLiteral(it) => node!(RegExpLiteral, it),
        Expression::StringLiteral(it) => node!(StringLiteral, it),
        Expression::TemplateLiteral(it) => node!(TemplateLiteral, it),
        Expression::Identifier(it) => node!(IdentifierReference, it),
        Expression::MetaProperty(it) => node!(MetaProperty, it),
        Expression::Super(it) => node!(Super, it),
        Expression::ArrayExpression(it) => node!(ArrayExpression, it),
        Expression::ArrowFunctionExpression(it) => node!(ArrowFunctionExpression, it),
        Expression::AssignmentExpression(it) => node!(AssignmentExpression, it),
        Expression::AwaitExpression(it) => node!(AwaitExpression, it),
        Expression::BinaryExpression(it) => node!(BinaryExpression, it),
        // A bare `?.` link outside a ChainExpression only occurs in
        // recovered sources (`a?.b`t``); Babel still calls it Optional*.
        Expression::CallExpression(it) => call(
            it,
            if it.optional {
                1 + links_below(&it.callee)
            } else {
                0
            },
        ),
        Expression::ChainExpression(chain) => {
            chain_element(&chain.expression, optional_links(&chain.expression))
        }
        Expression::ClassExpression(it) => class(it),
        Expression::ConditionalExpression(it) => node!(ConditionalExpression, it),
        Expression::FunctionExpression(it) => node!(Function, it),
        Expression::ImportExpression(it) => node!(ImportExpression, it),
        Expression::LogicalExpression(it) => node!(LogicalExpression, it),
        Expression::NewExpression(it) => node!(NewExpression, it),
        Expression::ObjectExpression(it) => node!(ObjectExpression, it),
        Expression::ParenthesizedExpression(it) => expression(&it.expression),
        Expression::SequenceExpression(it) => node!(SequenceExpression, it),
        Expression::TaggedTemplateExpression(it) => node!(TaggedTemplateExpression, it),
        Expression::ThisExpression(it) => node!(ThisExpression, it),
        Expression::UnaryExpression(it) => node!(UnaryExpression, it),
        Expression::UpdateExpression(it) => node!(UpdateExpression, it),
        Expression::YieldExpression(it) => node!(YieldExpression, it),
        Expression::PrivateInExpression(it) => node!(PrivateInExpression, it),
        Expression::JSXElement(it) => node!(JSXElement, it),
        Expression::JSXFragment(it) => node!(JSXFragment, it),
        Expression::TSAsExpression(it) => node!(TSAsExpression, it),
        Expression::TSSatisfiesExpression(it) => node!(TSSatisfiesExpression, it),
        Expression::TSTypeAssertion(it) => node!(TSTypeAssertion, it),
        Expression::TSNonNullExpression(it) => non_null(it, 0),
        Expression::TSInstantiationExpression(it) => node!(TSInstantiationExpression, it),
        Expression::V8IntrinsicExpression(it) => node!(V8IntrinsicExpression, it),
        Expression::ComputedMemberExpression(_)
        | Expression::StaticMemberExpression(_)
        | Expression::PrivateFieldExpression(_) => {
            let member_expression = value.as_member_expression().expect("member variant");
            let chain = if member_expression.optional() {
                1 + links_below(member_expression.object())
            } else {
                0
            };
            member(member_expression, chain)
        }
    }
}

/// A class; Babel starts it at its first decorator, which oxc leaves
/// outside the class span when it precedes `export`.
pub(super) fn class<'a>(class: &'a Class<'a>) -> Node<'a> {
    let start = class
        .decorators
        .first()
        .map_or(class.span.start, |d| d.span.start.min(class.span.start));
    Node::new(
        NodeKind::Class(class),
        Span::new(start, class.span.end),
        class.node_id(),
    )
}

pub(super) fn member<'a>(member: &'a MemberExpression<'a>, chain: u32) -> Node<'a> {
    let node = match member {
        MemberExpression::ComputedMemberExpression(it) => it.node_id(),
        MemberExpression::StaticMemberExpression(it) => it.node_id(),
        MemberExpression::PrivateFieldExpression(it) => it.node_id(),
    };
    Node::new(NodeKind::Member { member, chain }, member.span(), node)
}

pub(super) fn call<'a>(call: &'a CallExpression<'a>, chain: u32) -> Node<'a> {
    Node::new(NodeKind::Call { call, chain }, call.span, call.node_id())
}

pub(super) fn non_null<'a>(expression: &'a TSNonNullExpression<'a>, chain: u32) -> Node<'a> {
    Node::new(
        NodeKind::TSNonNullExpression { expression, chain },
        expression.span,
        expression.node_id(),
    )
}

fn chain_element<'a>(element: &'a ChainElement<'a>, chain: u32) -> Node<'a> {
    match element {
        ChainElement::CallExpression(it) => call(it, chain),
        ChainElement::TSNonNullExpression(it) => non_null(it, chain),
        _ => member(
            element.as_member_expression().expect("member variant"),
            chain,
        ),
    }
}

/// Optional links (`?.`) on the spine of one oxc chain.
fn optional_links(element: &ChainElement<'_>) -> u32 {
    let (count, next) = match element {
        ChainElement::CallExpression(it) => (u32::from(it.optional), &it.callee),
        ChainElement::TSNonNullExpression(it) => (0, &it.expression),
        _ => {
            let member = element.as_member_expression().expect("member variant");
            (u32::from(member.optional()), member.object())
        }
    };
    count + links_below(next)
}

/// Optional links on a spine starting at `next`.
fn links_below(mut next: &Expression<'_>) -> u32 {
    let mut count = 0;
    loop {
        next = match next {
            Expression::CallExpression(it) => {
                count += u32::from(it.optional);
                &it.callee
            }
            Expression::TSNonNullExpression(it) => &it.expression,
            Expression::ComputedMemberExpression(_)
            | Expression::StaticMemberExpression(_)
            | Expression::PrivateFieldExpression(_) => {
                let member = next.as_member_expression().expect("member variant");
                count += u32::from(member.optional());
                member.object()
            }
            _ => return count,
        };
    }
}

/// A chain-spine child (member object, call callee, non-null operand) given
/// the optional links still below it.
pub(super) fn spine<'a>(child: &'a Expression<'a>, chain: u32) -> Node<'a> {
    if chain == 0 {
        return expression(child);
    }
    match child {
        Expression::CallExpression(it) => call(it, chain),
        Expression::TSNonNullExpression(it) => non_null(it, chain),
        Expression::ComputedMemberExpression(_)
        | Expression::StaticMemberExpression(_)
        | Expression::PrivateFieldExpression(_) => {
            member(child.as_member_expression().expect("member variant"), chain)
        }
        _ => expression(child),
    }
}
