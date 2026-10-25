//! `semanticReferenceRole` from `javascriptSemanticProjection.ts`: whether an
//! `Identifier` is a lexical read, write or export, or no reference at all.
//! The definitions pass needs it for prototype uncertainty; the rest of the
//! projection module (callables, module links, references) is D1 stage 2
//! and should extend this file rather than reinterpret identifier roles.

use crate::javascript::ast::{Field, Node};

use super::ast_values::{is_function, wrapped_write_site};

/// `JavaScriptSemanticReference["role"]`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ReferenceRole {
    Read,
    Write,
    Export,
}

/// `semanticReferenceRole`; `None` for declarations and non-reference keys.
pub fn reference_role<'a>(
    source: &'a str,
    node: &Node<'a>,
    parent: &Node<'a>,
) -> Option<ReferenceRole> {
    if is_declaration_identifier(source, node, parent) || is_non_reference_key(source, node, parent)
    {
        return None;
    }
    let is = |field| is_field(source, parent, field, node);
    match parent.babel_type() {
        "AssignmentPattern" if is(Field::Left) => return None,
        "AssignmentExpression" if is(Field::Left) => Some(ReferenceRole::Write),
        "UpdateExpression" => Some(ReferenceRole::Write),
        "ForInStatement" | "ForOfStatement" if is(Field::Left) => Some(ReferenceRole::Write),
        "ExportSpecifier" if is(Field::Local) => Some(ReferenceRole::Export),
        _ => Some(ReferenceRole::Read),
    }
}

/// Classify a reference with the enclosing-pattern rules used by the TS
/// projection. Destructuring identifiers need ancestry because their direct
/// property/array parent does not distinguish declarations from assignments.
pub fn semantic_reference_role<'a>(
    source: &'a str,
    node: &Node<'a>,
    parent: &Node<'a>,
    ancestors: &[Node<'a>],
) -> Option<ReferenceRole> {
    let mut chain = ancestors.to_vec();
    chain.push(*parent);

    for (index, candidate) in chain.iter().enumerate().rev() {
        if !is_pattern_node(candidate) || !binds_identifier(source, candidate, parent, node) {
            continue;
        }
        for owner in chain[..index].iter().rev() {
            if matches!(
                owner.babel_type(),
                "AssignmentExpression" | "ForInStatement" | "ForOfStatement"
            ) {
                return Some(ReferenceRole::Write);
            }
            if is_pattern_owner_declaration(source, owner) {
                if candidate.babel_type() == "RestElement" {
                    if is_assigned_function(source, owner, &chain[..index]) {
                        return Some(ReferenceRole::Write);
                    }
                }
                return None;
            }
        }

        // Babel's `semanticIdentifierRole` falls through to the ordinary
        // reference classifier when a pattern has no declaration/write owner.
        // This is observable for type-only callable signatures, whose rest
        // parameters are references even though their AST uses RestElement.
        break;
    }
    if let Some(site) = wrapped_write_site(source, node, parent, ancestors)
        && site.key() != parent.key()
        && !(site.babel_type() == "UnaryExpression" && site.operator() == Some("delete"))
    {
        return Some(ReferenceRole::Write);
    }
    reference_role(source, node, parent)
}

fn is_assigned_function<'a>(source: &'a str, function: &Node<'a>, ancestors: &[Node<'a>]) -> bool {
    is_function(function)
        && function
            .field_list(source, Field::Params)
            .into_iter()
            .flatten()
            .all(|parameter| !is_declaration_pattern(&parameter))
        && ancestors.iter().any(|ancestor| {
            ancestor.babel_type() == "AssignmentExpression"
                && ancestor
                    .field(source, Field::Right)
                    .is_some_and(|right| right.key() == function.key())
        })
}

fn binds_identifier<'a>(
    source: &'a str,
    pattern: &Node<'a>,
    parent: &Node<'a>,
    node: &Node<'a>,
) -> bool {
    if pattern.key() == node.key() {
        return true;
    }

    // Oxc exposes a binding identifier directly below its pattern in several
    // cases where Babel's visitor callback reports the pattern itself as the
    // immediate parent.  The TypeScript implementation uses the pattern's
    // containment relation for this shape, so preserve that relation before
    // checking the property/element-specific cases below.
    if pattern.key() == parent.key() {
        return pattern_contains(source, pattern, node);
    }

    match pattern.babel_type() {
        "ObjectPattern" => pattern
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
            .any(|property| {
                property.key() == parent.key()
                    && (property
                        .field(source, Field::Value)
                        .is_some_and(|value| value.key() == node.key())
                        || (property
                            .field(source, Field::Key)
                            .is_some_and(|key| key.key() == node.key() && property.shorthand())))
            }),
        "ArrayPattern" => pattern
            .field_list(source, Field::Elements)
            .into_iter()
            .flatten()
            .any(|element| element.key() == parent.key()),
        "AssignmentPattern" => pattern
            .field(source, Field::Left)
            .is_some_and(|left| left.key() == parent.key()),
        "RestElement" => pattern
            .field(source, Field::Argument)
            .is_some_and(|argument| argument.key() == parent.key()),
        _ => false,
    }
}

fn is_pattern_owner_declaration<'a>(source: &'a str, node: &Node<'a>) -> bool {
    if node.babel_type() == "TSParameterProperty" {
        return true;
    }
    if node.babel_type() == "VariableDeclarator" {
        return node
            .field(source, Field::Id)
            .is_some_and(|id| is_pattern_node(&id));
    }
    if is_function(node) {
        return node
            .field_list(source, Field::Params)
            .into_iter()
            .flatten()
            .any(|parameter| is_declaration_pattern(&parameter));
    }
    node.babel_type() == "CatchClause"
        && node
            .field(source, Field::Param)
            .is_some_and(|param| is_pattern_node(&param))
}

/// Babel's `t.isPattern` excludes a bare `RestElement`.  That distinction is
/// observable here: a rest-only parameter is emitted as a read, while a rest
/// parameter beside an object/array/default pattern is a declaration slot.
fn is_declaration_pattern(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "ObjectPattern" | "ArrayPattern" | "AssignmentPattern"
    )
}

/// Pattern-shaped nodes that can contain a bound identifier.
fn is_pattern_node(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "ObjectPattern" | "ArrayPattern" | "AssignmentPattern" | "RestElement"
    )
}

fn is_field<'a>(source: &'a str, parent: &Node<'a>, field: Field, child: &Node<'a>) -> bool {
    parent
        .field(source, field)
        .is_some_and(|value| value.key() == child.key())
}

fn is_declaration_identifier<'a>(source: &'a str, node: &Node<'a>, parent: &Node<'a>) -> bool {
    let is = |field| is_field(source, parent, field, node);
    let contains = |field| {
        parent
            .field(source, field)
            .is_some_and(|pattern| pattern_contains(source, &pattern, node))
    };
    match parent.babel_type() {
        "TSImportEqualsDeclaration" => return is(Field::Id),
        "TSParameterProperty" if contains(Field::Parameter) => return true,
        "VariableDeclarator" if contains(Field::Id) => return true,
        "FunctionDeclaration" | "FunctionExpression" if is(Field::Id) => return true,
        "ClassDeclaration" | "ClassExpression" if is(Field::Id) => return true,
        "ImportSpecifier" if is(Field::Local) || is(Field::Imported) => return true,
        "ImportDefaultSpecifier" | "ImportNamespaceSpecifier" if is(Field::Local) => return true,
        "CatchClause" if is(Field::Param) => return true,
        _ => {}
    }
    is_function(parent)
        && parent
            .field_list(source, Field::Params)
            .into_iter()
            .flatten()
            .any(|param| pattern_contains(source, &param, node))
}

fn is_non_reference_key<'a>(source: &'a str, node: &Node<'a>, parent: &Node<'a>) -> bool {
    let is = |field| is_field(source, parent, field, node);
    match parent.babel_type() {
        "MemberExpression" | "OptionalMemberExpression" => {
            is(Field::Property) && !parent.computed()
        }
        "ObjectProperty" => is(Field::Key) && !parent.computed() && !parent.shorthand(),
        "ObjectMethod" => is(Field::Key) && !parent.computed(),
        "ClassMethod" | "ClassProperty" | "TSDeclareMethod" => is(Field::Key) && !parent.computed(),
        "PrivateName" | "LabeledStatement" | "BreakStatement" | "ContinueStatement" => true,
        "ExportSpecifier" => is(Field::Exported),
        _ => false,
    }
}

/// `patternContains`.
fn pattern_contains<'a>(source: &'a str, pattern: &Node<'a>, target: &Node<'a>) -> bool {
    if pattern.key() == target.key() {
        return true;
    }
    let inner = |field| {
        pattern
            .field(source, field)
            .is_some_and(|inner| pattern_contains(source, &inner, target))
    };
    match pattern.babel_type() {
        "TSParameterProperty" => inner(Field::Parameter),
        "AssignmentPattern" => inner(Field::Left),
        "RestElement" => inner(Field::Argument),
        "ObjectPattern" => pattern
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
            .any(|property| {
                let field = if property.babel_type() == "RestElement" {
                    Field::Argument
                } else {
                    Field::Value
                };
                property
                    .field(source, field)
                    .is_some_and(|inner| pattern_contains(source, &inner, target))
            }),
        "ArrayPattern" => pattern
            .field_list(source, Field::Elements)
            .into_iter()
            .flatten()
            .any(|element| pattern_contains(source, &element, target)),
        _ => false,
    }
}
