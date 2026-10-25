//! Port of `javascriptGraphqlOperations.ts`: named GraphQL operations from
//! document text, precompiled document objects and GraphQL `Source`
//! literals whose ownership is proven private.

use std::collections::{HashMap, HashSet};

use super::babel::same;
use super::helpers::range;
use super::semantics::{BindingFacts, StableInitializer, StaticSemantics};
use crate::javascript::ast::{AstContext, Field, Node, NodeKey, NodeSet};
use crate::javascript::semantic::ast_values::{
    final_object_property, final_object_string_property, static_property_key, unwrapped,
};

/// One recovered operation (`JavaScriptRpcEndpoint`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphqlOperation {
    pub value: String,
    /// `graphql:query`, `graphql:mutation` or `graphql:subscription`.
    pub mechanism: String,
}

impl GraphqlOperation {
    fn key(&self) -> String {
        format!("{}:{}", self.mechanism, self.value)
    }
}

const OPERATION_TYPES: [&str; 3] = ["query", "mutation", "subscription"];

// GraphQL October 2021 §2.1.7: ignored BOM, tab/space, line endings and
// commas; comments run to the next line ending. Indices are byte offsets;
// every character the lexer compares is ASCII or U+FEFF, so they denote the
// same positions as the TS UTF-16 indices.
fn skip_ignored(text: &str, start: usize) -> usize {
    let mut index = start;
    let mut chars = text[start.min(text.len())..].chars().peekable();
    while let Some(&character) = chars.peek() {
        match character {
            ',' | '\u{FEFF}' | '\t' | ' ' | '\n' | '\r' => {
                index += character.len_utf8();
                chars.next();
            }
            '#' => {
                while let Some(&inner) = chars.peek() {
                    if inner == '\n' || inner == '\r' {
                        break;
                    }
                    index += inner.len_utf8();
                    chars.next();
                }
            }
            _ => break,
        }
    }
    index
}

fn char_at(text: &str, index: usize) -> Option<char> {
    text.get(index..).and_then(|rest| rest.chars().next())
}

/// `/^[_A-Za-z][_0-9A-Za-z]*/u` at `index`: the name and its end.
fn name_at(text: &str, index: usize) -> Option<(&str, usize)> {
    let rest = text.get(index..)?;
    let bytes = rest.as_bytes();
    if !bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let length = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
        .count();
    Some((&rest[..length], index + length))
}

/// `graphqlOperationFromText`.
pub fn graphql_operation_from_text(text: &str) -> Option<GraphqlOperation> {
    let (kind, kind_end) = name_at(text, skip_ignored(text, 0))?;
    if !OPERATION_TYPES.contains(&kind) {
        return None;
    }
    let (name, name_end) = name_at(text, skip_ignored(text, kind_end))?;
    let index = skip_ignored(text, name_end);
    let next = char_at(text, index);
    // A named operation followed by variable definitions, a directive, or a
    // selection set with a field.
    let has_header = match next {
        Some('(') => char_at(text, skip_ignored(text, index + 1)) == Some('$'),
        Some('@' | '{') => name_at(text, skip_ignored(text, index + 1)).is_some(),
        _ => false,
    };
    has_header.then(|| GraphqlOperation {
        value: name.to_owned(),
        mechanism: format!("graphql:{kind}"),
    })
}

/// `graphqlOperationFromDocumentNode`.
fn operation_from_document_node<'a>(source: &'a str, node: Node<'a>) -> Option<GraphqlOperation> {
    if final_object_string_property(source, node, "kind") != Some("OperationDefinition") {
        return None;
    }
    let kind = final_object_string_property(source, node, "operation")
        .filter(|kind| OPERATION_TYPES.contains(kind))?;
    let name = final_object_property(source, node, "name")
        .filter(|name| name.babel_type() == "ObjectExpression")?;
    if final_object_string_property(source, name, "kind") != Some("Name") {
        return None;
    }
    let value = final_object_string_property(source, name, "value")?;
    Some(GraphqlOperation {
        value: value.to_owned(),
        mechanism: format!("graphql:{kind}"),
    })
}

/// `graphqlOperationFromTemplate`: continue only across quasis made of
/// ignored tokens; dynamic text before an operation stops the claim.
fn operation_from_template<'a>(source: &'a str, node: &Node<'a>) -> Option<GraphqlOperation> {
    for quasi in node.field_list(source, Field::Quasis).into_iter().flatten() {
        let cooked = quasi.template_cooked()?;
        if skip_ignored(cooked, 0) == cooked.len() {
            continue;
        }
        return graphql_operation_from_text(cooked);
    }
    None
}

fn property_named<'a>(source: &'a str, property: &Node<'a>, name: &str) -> bool {
    property.babel_type() == "ObjectProperty"
        && property
            .field(source, Field::Key)
            .and_then(|key| static_property_key(source, key, property.computed()))
            .is_some_and(|key| key == name)
}

/// `graphqlSourceBodyLiterals`: `body` strings owned by a `Source`-shaped
/// literal, including those of inline object spreads.
fn source_body_literals<'a>(source: &'a str, node: &Node<'a>) -> Option<Vec<Node<'a>>> {
    let properties = |object: &Node<'a>| -> Vec<Node<'a>> {
        object
            .field_list(source, Field::Properties)
            .into_iter()
            .flatten()
            .collect()
    };
    if !properties(node)
        .iter()
        .any(|property| property_named(source, property, "locationOffset"))
    {
        return None;
    }
    let body_strings = |object: &Node<'a>| -> Vec<Node<'a>> {
        properties(object)
            .into_iter()
            .filter(|property| property_named(source, property, "body"))
            .filter_map(|property| property.field(source, Field::Value))
            .filter(|value| value.babel_type() == "StringLiteral")
            .collect()
    };
    let spreads = |object: &Node<'a>| -> Vec<Node<'a>> {
        properties(object)
            .into_iter()
            .filter(|property| property.babel_type() == "SpreadElement")
            .filter_map(|property| property.field(source, Field::Argument))
            .map(|argument| unwrapped(source, argument))
            .filter(|spread| spread.babel_type() == "ObjectExpression")
            .collect()
    };
    let mut bodies = body_strings(node);
    let mut visited: NodeSet = NodeSet::default();
    visited.insert(node.key());
    let mut pending = spreads(node);
    while let Some(current) = pending.pop() {
        if !visited.insert(current.key()) {
            continue;
        }
        bodies.extend(body_strings(&current));
        pending.extend(spreads(&current));
    }
    (!bodies.is_empty()).then_some(bodies)
}

#[derive(Clone, Debug)]
struct Dependency {
    binding_id: String,
    name: String,
    /// JSON of the read's source range, when the dependency is a read.
    location: Option<String>,
}

struct SourceCopy {
    source: NodeKey,
    dependencies: Vec<Dependency>,
    operations: Vec<GraphqlOperation>,
}

struct PendingSource<'a> {
    source: NodeKey,
    node: Node<'a>,
    operation: GraphqlOperation,
}

/// One finding from [`GraphqlScan::finish`]: the `body` literal and its
/// operation.
#[derive(Clone, Debug)]
pub struct GraphqlSourceFinding<'a> {
    pub node: Node<'a>,
    pub operation: GraphqlOperation,
}

/// `createJavaScriptGraphqlScan`: feed every node in pre-order through
/// [`inspect`](Self::inspect), then drain [`finish`](Self::finish).
pub struct GraphqlScan<'s, 'a> {
    cx: &'s AstContext<'a>,
    semantics: &'s dyn StaticSemantics<'a>,
    bodies: NodeSet,
    copies: Vec<SourceCopy>,
    sources: Vec<PendingSource<'a>>,
}

impl<'s, 'a> GraphqlScan<'s, 'a> {
    pub fn new(cx: &'s AstContext<'a>, semantics: &'s dyn StaticSemantics<'a>) -> Self {
        Self {
            cx,
            semantics,
            bodies: NodeSet::default(),
            copies: Vec::new(),
            sources: Vec::new(),
        }
    }

    fn source(&self) -> &'a str {
        self.cx.source()
    }

    /// `inspect(node)`.
    pub fn inspect(&mut self, node: &Node<'a>) -> Option<GraphqlOperation> {
        let source = self.source();
        match node.babel_type() {
            "StringLiteral" => {
                return if self.bodies.contains(&node.key()) {
                    None
                } else {
                    graphql_operation_from_text(node.string_value().unwrap_or(""))
                };
            }
            "TemplateLiteral" => return operation_from_template(source, node),
            "ObjectExpression" => {}
            _ => return None,
        }
        let operation = operation_from_document_node(source, *node);
        if final_object_property(source, *node, "loc").is_some() {
            let operations = document_operations(source, *node, operation.clone());
            if !operations.is_empty()
                && let Some((copy_source, dependencies)) = self.document_source(*node)
            {
                self.copies.push(SourceCopy {
                    source: copy_source.key(),
                    dependencies,
                    operations,
                });
            }
        }
        if let Some(owned) = source_body_literals(source, node) {
            for body in &owned {
                self.bodies.insert(body.key());
            }
            if let Some(body) = final_object_property(source, *node, "body")
                .filter(|it| it.babel_type() == "StringLiteral")
                && let Some(recovered) =
                    graphql_operation_from_text(body.string_value().unwrap_or(""))
            {
                self.sources.push(PendingSource {
                    source: node.key(),
                    node: body,
                    operation: recovered,
                });
            }
        }
        operation
    }

    /// `finish()`: `Source` body operations whose source object is not a
    /// proven private copy of an already reported document.
    pub fn finish(&mut self) -> Vec<GraphqlSourceFinding<'a>> {
        let mut copied: HashMap<NodeKey, HashSet<String>> = HashMap::new();
        // The source object is observable through direct eval.  In an ES
        // module, a default export also exposes the document's source object
        // through the module boundary.  Both cases defeat the private-copy
        // proof used below, so retain the source operation.
        let ownership_is_observable =
            self.source().contains("eval(") || self.source().contains("export default");
        if !self.sources.is_empty() && !self.copies.is_empty() {
            let references = self.semantics.references();
            let mut uncertain = uncertain_bindings(&self.copies, &references);
            // Direct eval can inspect private source objects even when the
            // semantic reference projection does not expose the eval call.
            // Calls using a source binding are likewise observable ownership
            // escapes and must prevent copy suppression.
            if self.source().contains("eval(") {
                uncertain.extend(
                    self.copies
                        .iter()
                        .flat_map(|copy| copy.dependencies.iter())
                        .map(|dependency| dependency.binding_id.clone()),
                );
            }
            for copy in &self.copies {
                for dependency in &copy.dependencies {
                    let call_prefix = format!("{}(", dependency.name);
                    if self.source().contains(&call_prefix) {
                        uncertain.insert(dependency.binding_id.clone());
                    }
                }
            }
            for copy in &self.copies {
                if copy
                    .dependencies
                    .iter()
                    .all(|dependency| !uncertain.contains(&dependency.binding_id))
                {
                    let keys = copied.entry(copy.source).or_default();
                    keys.extend(copy.operations.iter().map(GraphqlOperation::key));
                }
            }
        }
        let findings = self
            .sources
            .drain(..)
            .filter(|pending| {
                ownership_is_observable
                    || !copied
                        .get(&pending.source)
                        .is_some_and(|keys| keys.contains(&pending.operation.key()))
            })
            .map(|pending| GraphqlSourceFinding {
                node: pending.node,
                operation: pending.operation,
            })
            .collect();
        self.copies.clear();
        findings
    }

    /// `graphqlPrivateBinding`: one private constant owns its initializer.
    fn private_binding(
        &self,
        node: &Node<'a>,
    ) -> Option<(&'s BindingFacts, StableInitializer<'a>)> {
        let binding = self.semantics.binding(node)?;
        if binding.mutable {
            return None;
        }
        match binding.scope_kind.as_deref() {
            None => return None,
            Some("program") if !self.semantics.is_module() => return None,
            _ => {}
        }
        let initializer = self.semantics.stable_initializer(&binding.binding_id)?;
        if initializer.projection_len != 0 {
            return None;
        }
        let declaration = self.semantics.parent(&initializer.node)?;
        if declaration.babel_type() != "VariableDeclarator" {
            return None;
        }
        let statement = self.semantics.parent(&declaration)?;
        if statement.babel_type() != "VariableDeclaration"
            || self.semantics.parent(&statement).is_some_and(|parent| {
                matches!(
                    parent.babel_type(),
                    "ExportNamedDeclaration" | "ExportDefaultDeclaration"
                )
            })
        {
            return None;
        }
        Some((binding, initializer))
    }

    /// `graphqlSourceObjectValue`.
    fn source_object_value(
        &self,
        node: Option<Node<'a>>,
        dependencies: &mut Vec<Dependency>,
    ) -> Option<Node<'a>> {
        let mut node = node?;
        let mut visited: NodeSet = NodeSet::default();
        while visited.insert(node.key()) {
            node = unwrapped(self.source(), node);
            if node.babel_type() == "ObjectExpression" {
                return Some(node);
            }
            if node.babel_type() != "Identifier" {
                return None;
            }
            let (binding, initializer) = self.private_binding(&node)?;
            if initializer.node.span().end > node.span().start {
                return None;
            }
            let location = serde_json::to_string(&range(self.cx, &node)).unwrap_or_default();
            dependencies.push(Dependency {
                binding_id: binding.binding_id.clone(),
                name: binding.name.clone(),
                location: Some(location),
            });
            node = initializer.node;
        }
        None
    }

    /// `graphqlDocumentSource`.
    fn document_source(&self, node: Node<'a>) -> Option<(Node<'a>, Vec<Dependency>)> {
        let source = self.source();
        let mut dependencies = Vec::new();
        let loc = self.source_object_value(
            final_object_property(source, node, "loc"),
            &mut dependencies,
        )?;
        let copy_source = self.source_object_value(
            final_object_property(source, loc, "source"),
            &mut dependencies,
        )?;
        self.container_ownership(node, &mut dependencies)
            .then_some((copy_source, dependencies))
    }

    /// `graphqlContainerOwnership`: follow containment to the binding that
    /// can expose or mutate this document.
    fn container_ownership(&self, document: Node<'a>, dependencies: &mut Vec<Dependency>) -> bool {
        let source = self.source();
        let mut node = document;
        loop {
            let Some(parent) = self.semantics.parent(&node) else {
                return false;
            };
            let kind = parent.babel_type();
            if kind == "ObjectProperty"
                && parent
                    .field(source, Field::Value)
                    .is_some_and(|value| same(&value, &node))
            {
                match self.semantics.parent(&parent) {
                    Some(object) if object.babel_type() == "ObjectExpression" => node = object,
                    _ => return false,
                }
            } else if kind == "ArrayExpression" || same(&unwrapped(source, parent), &node) {
                node = parent;
            } else if kind == "ExpressionStatement" {
                return true;
            } else if kind == "VariableDeclarator"
                && parent
                    .field(source, Field::Init)
                    .is_some_and(|init| same(&init, &node))
            {
                let Some(id) = parent
                    .field(source, Field::Id)
                    .filter(|id| id.babel_type() == "Identifier")
                else {
                    return false;
                };
                let Some((binding, initializer)) = self.private_binding(&id) else {
                    return false;
                };
                if !same(&initializer.node, &node) {
                    return false;
                }
                dependencies.push(Dependency {
                    binding_id: binding.binding_id.clone(),
                    name: binding.name.clone(),
                    location: None,
                });
                return true;
            } else {
                return false;
            }
        }
    }
}

/// `graphqlDocumentOperations`.
fn document_operations<'a>(
    source: &'a str,
    node: Node<'a>,
    operation: Option<GraphqlOperation>,
) -> Vec<GraphqlOperation> {
    if let Some(operation) = operation {
        return vec![operation];
    }
    if final_object_string_property(source, node, "kind") != Some("Document") {
        return Vec::new();
    }
    match final_object_property(source, node, "definitions") {
        Some(definitions) if definitions.babel_type() == "ArrayExpression" => definitions
            .field_list(source, Field::Elements)
            .into_iter()
            .flatten()
            .filter(|definition| definition.babel_type() == "ObjectExpression")
            .filter_map(|definition| operation_from_document_node(source, definition))
            .collect(),
        _ => Vec::new(),
    }
}

/// `graphqlSourceReferenceIndexSteps` + `uncertainGraphqlSourceBindingsSteps`:
/// any non-metadata use makes its connected alias component uncertain.
fn uncertain_bindings(
    copies: &[SourceCopy],
    references: &[super::semantics::SemanticReference],
) -> HashSet<String> {
    let mut allowed: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut neighbors: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut by_name: HashMap<&str, Vec<&str>> = HashMap::new();
    for copy in copies {
        let first = copy.dependencies.first().map(|it| it.binding_id.as_str());
        for dependency in &copy.dependencies {
            let id = dependency.binding_id.as_str();
            let sites = allowed.entry(id).or_default();
            if let Some(location) = &dependency.location {
                sites.insert(location);
            }
            let names = by_name.entry(dependency.name.as_str()).or_default();
            if !names.contains(&id) {
                names.push(id);
            }
            let Some(first) = first.filter(|first| *first != id) else {
                continue;
            };
            neighbors.entry(first).or_default().insert(id);
            neighbors.entry(id).or_default().insert(first);
        }
    }
    let mut uncertain: HashSet<String> = HashSet::new();
    for reference in references {
        // Direct eval may reach private lexical objects.
        if reference.name == "eval" {
            return allowed.keys().map(|id| (*id).to_owned()).collect();
        }
        if let Some(id) = &reference.binding_id {
            if let Some(sites) = allowed.get(id.as_str()) {
                let location = serde_json::to_string(&reference.location).unwrap_or_default();
                if reference.role != "read" || !sites.contains(location.as_str()) {
                    uncertain.insert(id.clone());
                }
            }
        } else if reference.resolution == "unknown" || reference.resolution == "ambiguous" {
            for id in by_name.get(reference.name.as_str()).into_iter().flatten() {
                uncertain.insert((*id).to_owned());
            }
        }
    }
    let mut pending: Vec<String> = uncertain.iter().cloned().collect();
    while let Some(id) = pending.pop() {
        for neighbor in neighbors.get(id.as_str()).into_iter().flatten() {
            if uncertain.insert((*neighbor).to_owned()) {
                pending.push((*neighbor).to_owned());
            }
        }
    }
    uncertain
}
