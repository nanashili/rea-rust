//! Source-order and effect-timing helpers for semantic binding mutations.
//!
//! The definitions pass owns bindings and the parent map. This module only
//! derives temporal facts from those records, preserving unknown ordering
//! instead of treating it as a later write.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{Field, Node, NodeKey, NodeParents};

use super::ast_values::{is_member, static_property_key, unwrapped};
use super::evaluation_order::{
    IterationCardinality, branch_may_be_skipped, delayed_instance_field_value,
    iteration_cardinality,
};
use super::state::{BindingState, Initializer, ReferenceInitializer, SemanticState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementPosition {
    pub body: NodeKey,
    /// Statement index, or `-1` for a function/body entry position.
    pub index: isize,
    pub declarator_index: isize,
}

/// Per-analysis memo for source-order facts.
///
/// Node keys are only unique within one AST, so this cache is deliberately
/// owned by the current analysis rather than shared globally. `None` entries
/// are retained as well: an unresolved branch/loop context is a semantic fact
/// and repeatedly recomputing it was the hot path in large applications.
#[derive(Default)]
pub struct StatementPositionCache {
    body_indexes: HashMap<NodeKey, BodyPositionIndex>,
    unindexed_bodies: HashSet<NodeKey>,
    body_index_entries: usize,
    body_index_entry_limit: Option<usize>,
    direct_mutations: HashMap<NodeKey, Option<StatementPosition>>,
    direct_initializers: HashMap<NodeKey, Option<StatementPosition>>,
    reference_initializers: HashMap<NodeKey, Option<StatementPosition>>,
    binding_reads: HashMap<NodeKey, BindingReadPosition>,
    position_entries: usize,
}

const STATEMENT_POSITION_CACHE_ENTRY_LIMIT: usize = 16_384;

#[derive(Default)]
struct BodyPositionIndex {
    statements: HashMap<NodeKey, isize>,
    declarators: HashMap<(NodeKey, NodeKey), isize>,
}

impl StatementPositionCache {
    fn admit_position(&mut self) {
        if self.position_entries >= STATEMENT_POSITION_CACHE_ENTRY_LIMIT {
            // These maps contain facts derived solely from the immutable AST.
            // Rotate the bounded generation instead of permanently disabling
            // admission for every later node in a large source file.
            self.direct_mutations.clear();
            self.direct_initializers.clear();
            self.reference_initializers.clear();
            self.binding_reads.clear();
            self.position_entries = 0;
        }
        self.position_entries += 1;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingReadPosition {
    pub position: Option<StatementPosition>,
    pub repeating: bool,
}

#[derive(Clone, Debug)]
pub struct SemanticBindingRead<'s, 'a> {
    pub status: BindingReadStatus,
    pub has_definite_initializer: bool,
    pub binding: Cow<'s, BindingState<'a>>,
    /// Consumers must use `binding` when temporal selection changed the
    /// initializer facts available at this read.
    pub selection_changed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingReadStatus {
    Ordered,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectTiming {
    Before,
    After,
    Unknown,
}

fn is_statement(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "ExpressionStatement"
            | "EmptyStatement"
            | "DebuggerStatement"
            | "ReturnStatement"
            | "ThrowStatement"
            | "BreakStatement"
            | "ContinueStatement"
            | "IfStatement"
            | "DoWhileStatement"
            | "WhileStatement"
            | "ForStatement"
            | "ForInStatement"
            | "ForOfStatement"
            | "SwitchStatement"
            | "TryStatement"
            | "WithStatement"
            | "VariableDeclaration"
            | "FunctionDeclaration"
            | "ClassDeclaration"
            | "LabeledStatement"
    )
}

fn is_loop(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "ForStatement"
            | "ForInStatement"
            | "ForOfStatement"
            | "WhileStatement"
            | "DoWhileStatement"
    )
}

fn is_function(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ObjectMethod"
            | "ClassMethod"
            | "ClassPrivateMethod"
    )
}

fn is_identifier(node: &Node<'_>) -> bool {
    matches!(
        node.babel_type(),
        "Identifier" | "IdentifierName" | "IdentifierReference"
    )
}

fn statement_position<'a>(
    statement: &Node<'a>,
    parents: &NodeParents<'a>,
    declarator: Option<&Node<'a>>,
    source: &str,
) -> Option<StatementPosition> {
    let parent = parents.get(&statement.key())?;
    if !matches!(parent.babel_type(), "Program" | "BlockStatement") {
        return None;
    }
    let body = parent.field_list(source, Field::Body);
    let index = body
        .iter()
        .position(|entry| entry.is_some_and(|entry| entry.key() == statement.key()))?;
    let index = isize::try_from(index).ok()?;
    let declarator_index = if statement.babel_type() == "VariableDeclaration" {
        declarator
            .and_then(|declarator| {
                statement
                    .field_list(source, Field::Declarations)
                    .iter()
                    .position(|entry| entry.is_some_and(|entry| entry.key() == declarator.key()))
            })
            .map_or(-1, |index| index as isize)
    } else {
        -1
    };
    Some(StatementPosition {
        body: parent.key(),
        index,
        declarator_index,
    })
}

fn body_position_index<'a, 'cache>(
    cache: &'cache mut StatementPositionCache,
    parent: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<&'cache BodyPositionIndex> {
    let body_key = parent.key();
    if cache.body_indexes.contains_key(&body_key) {
        return cache.body_indexes.get(&body_key);
    }
    if cache.unindexed_bodies.contains(&body_key) {
        return None;
    }

    let body = parent.field_list(source, Field::Body);
    let declarations = body
        .iter()
        .flatten()
        .filter(|statement| statement.babel_type() == "VariableDeclaration")
        .flat_map(|statement| statement.field_list(source, Field::Declarations))
        .flatten()
        .count();
    let body_entries = body.iter().flatten().count();
    let required_entries = body_entries.saturating_add(declarations);
    let entry_limit = *cache
        .body_index_entry_limit
        .get_or_insert_with(|| parents.len().saturating_mul(2));
    if required_entries > entry_limit.saturating_sub(cache.body_index_entries) {
        cache.unindexed_bodies.insert(body_key);
        return None;
    }

    let mut index = BodyPositionIndex::default();
    for (position, statement) in body.iter().enumerate() {
        let Some(statement) = statement else {
            continue;
        };
        let Ok(position) = isize::try_from(position) else {
            cache.unindexed_bodies.insert(body_key);
            return None;
        };
        index.statements.insert(statement.key(), position);
        if statement.babel_type() != "VariableDeclaration" {
            continue;
        }
        for (declarator_index, declarator) in statement
            .field_list(source, Field::Declarations)
            .iter()
            .enumerate()
        {
            let Some(declarator) = declarator else {
                continue;
            };
            let Ok(declarator_index) = isize::try_from(declarator_index) else {
                cache.unindexed_bodies.insert(body_key);
                return None;
            };
            index
                .declarators
                .insert((statement.key(), declarator.key()), declarator_index);
        }
    }
    cache.body_index_entries = cache.body_index_entries.saturating_add(required_entries);
    cache.body_indexes.insert(body_key, index);
    cache.body_indexes.get(&body_key)
}

fn cached_statement_position<'a>(
    cache: &mut StatementPositionCache,
    statement: &Node<'a>,
    parents: &NodeParents<'a>,
    declarator: Option<&Node<'a>>,
    source: &str,
) -> Option<StatementPosition> {
    let parent = parents.get(&statement.key()).copied()?;
    if !matches!(parent.babel_type(), "Program" | "BlockStatement") {
        return None;
    }
    let Some(index) = body_position_index(cache, parent, parents, source) else {
        return statement_position(statement, parents, declarator, source);
    };
    let statement_index = *index.statements.get(&statement.key())?;
    let declarator_index = if statement.babel_type() == "VariableDeclaration" {
        declarator
            .and_then(|declarator| {
                index
                    .declarators
                    .get(&(statement.key(), declarator.key()))
                    .copied()
            })
            .unwrap_or(-1)
    } else {
        -1
    };
    Some(StatementPosition {
        body: parent.key(),
        index: statement_index,
        declarator_index,
    })
}

fn precedes(left: StatementPosition, right: StatementPosition) -> bool {
    left.body == right.body
        && (left.index < right.index
            || (left.index == right.index
                && left.declarator_index >= 0
                && left.declarator_index < right.declarator_index))
}

fn expression_children<'a>(node: Node<'a>, source: &'a str) -> Option<Vec<Node<'a>>> {
    let children = match node.babel_type() {
        "SequenceExpression" => node.field_list(source, Field::Expressions),
        "ArrayExpression" => node.field_list(source, Field::Elements),
        "ObjectExpression" => node.field_list(source, Field::Properties),
        "ObjectProperty" => {
            if node.computed() {
                [
                    node.field(source, Field::Key),
                    node.field(source, Field::Value),
                ]
                .into_iter()
                .flatten()
                .map(Some)
                .collect()
            } else {
                node.field(source, Field::Value)
                    .into_iter()
                    .map(Some)
                    .collect()
            }
        }
        "CallExpression" | "OptionalCallExpression" | "NewExpression" => {
            let mut result = node
                .field(source, Field::Callee)
                .into_iter()
                .map(Some)
                .collect::<Vec<_>>();
            result.extend(node.field_list(source, Field::Arguments));
            result
        }
        "BinaryExpression" | "LogicalExpression" => [
            node.field(source, Field::Left),
            node.field(source, Field::Right),
        ]
        .into_iter()
        .map(|child| child.map(Some).unwrap_or(None))
        .collect(),
        "ConditionalExpression" => node
            .field(source, Field::Test)
            .into_iter()
            .map(Some)
            .collect(),
        _ => return None,
    };
    Some(children.into_iter().flatten().collect())
}

/// Compare two descendants of one expression using JavaScript evaluation order.
pub fn expression_evaluation_order<'a>(
    earlier: Node<'a>,
    later: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<bool> {
    let mut ancestors = Vec::new();
    let mut current = Some(earlier);
    while let Some(node) = current {
        ancestors.push(node);
        current = parents.get(&node.key()).copied();
    }

    let mut later_path = Vec::new();
    current = Some(later);
    let common = loop {
        let Some(node) = current else { return None };
        if let Some(index) = ancestors
            .iter()
            .position(|ancestor| ancestor.key() == node.key())
        {
            break (node, index);
        }
        later_path.push(node);
        current = parents.get(&node.key()).copied();
    };
    let earlier_child = ancestors.get(common.1.checked_sub(1)?).copied()?;
    let later_child = later_path.last().copied()?;
    let children = expression_children(common.0, source)?;
    let earlier_index = children
        .iter()
        .position(|child| child.key() == earlier_child.key())?;
    let later_index = children
        .iter()
        .position(|child| child.key() == later_child.key())?;
    (earlier_index != later_index).then_some(earlier_index < later_index)
}

fn direct_mutation_position<'a>(
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    let mut cache = StatementPositionCache::default();
    cached_direct_mutation_position(&mut cache, node, parents, source)
}

fn cached_direct_mutation_position<'a>(
    cache: &mut StatementPositionCache,
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    if let Some(position) = cache.direct_mutations.get(&node.key()) {
        return *position;
    }
    let position = if node.babel_type() == "ForOfStatement" {
        cached_statement_position(cache, &node, parents, None, source)
    } else if node.babel_type() == "VariableDeclarator" {
        parents.get(&node.key()).and_then(|declaration| {
            cached_statement_position(cache, declaration, parents, Some(&node), source)
        })
    } else if node.babel_type() == "SpreadElement" {
        parents.get(&node.key()).and_then(|array| {
            (array.babel_type() == "ArrayExpression")
                .then(|| cached_semantic_capture_position(cache, *array, parents, source))
                .flatten()
        })
    } else {
        let supported = matches!(
            node.babel_type(),
            "AssignmentExpression"
                | "UpdateExpression"
                | "CallExpression"
                | "OptionalCallExpression"
                | "NewExpression"
                | "TaggedTemplateExpression"
        ) || (node.babel_type() == "UnaryExpression"
            && node.operator() == Some("delete"));
        if !supported {
            None
        } else {
            let mut current = node;
            let mut result = None;
            loop {
                let Some(parent) = parents.get(&current.key()) else {
                    break;
                };
                if is_loop(parent)
                    || is_function(parent)
                    || branch_may_be_skipped(source, parent, &current)
                {
                    break;
                }
                if is_statement(parent) {
                    result = cached_statement_position(cache, parent, parents, None, source);
                    break;
                }
                if parent.babel_type() == "VariableDeclarator" {
                    let Some(declaration) = parents.get(&parent.key()) else {
                        break;
                    };
                    result = cached_statement_position(
                        cache,
                        declaration,
                        parents,
                        Some(parent),
                        source,
                    );
                    break;
                }
                current = *parent;
            }
            result
        }
    };
    cache.admit_position();
    cache.direct_mutations.insert(node.key(), position);
    position
}

fn direct_initializer_position<'a>(
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    let mut cache = StatementPositionCache::default();
    cached_direct_initializer_position(&mut cache, node, parents, source)
}

fn cached_direct_initializer_position<'a>(
    cache: &mut StatementPositionCache,
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    if let Some(position) = cache.direct_initializers.get(&node.key()) {
        return *position;
    }
    let position = if node.babel_type() == "UpdateExpression"
        || (node.babel_type() == "AssignmentExpression"
            && node
                .field(source, Field::Left)
                .is_some_and(|left| is_identifier(&left)))
    {
        cached_direct_mutation_position(cache, node, parents, source)
    } else {
        let parent = parents.get(&node.key());
        if parent.is_some_and(|parent| {
            parent.babel_type() == "VariableDeclarator"
                && parent
                    .field(source, Field::Init)
                    .is_some_and(|init| init.key() == node.key())
        }) {
            let declaration = parents.get(&parent.expect("checked above").key());
            declaration.and_then(|declaration| {
                cached_statement_position(
                    cache,
                    declaration,
                    parents,
                    Some(parent.expect("checked above")),
                    source,
                )
            })
        } else if parent.is_some_and(|parent| {
            parent.babel_type() == "AssignmentExpression"
                && parent
                    .field(source, Field::Right)
                    .is_some_and(|right| right.key() == node.key())
                && parent
                    .field(source, Field::Left)
                    .is_some_and(|left| is_identifier(&left))
        }) {
            cached_direct_mutation_position(cache, *parent.expect("checked above"), parents, source)
        } else {
            None
        }
    };
    cache.admit_position();
    cache.direct_initializers.insert(node.key(), position);
    position
}

fn reference_initializer_position<'a>(
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    let mut cache = StatementPositionCache::default();
    cached_reference_initializer_position(&mut cache, node, parents, source)
}

fn cached_reference_initializer_position<'a>(
    cache: &mut StatementPositionCache,
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    if let Some(position) = cache.reference_initializers.get(&node.key()) {
        return *position;
    }
    let mut current = node;
    let position = loop {
        if let Some(position) = cached_direct_initializer_position(cache, current, parents, source)
        {
            break Some(position);
        }
        let Some(parent) = parents.get(&current.key()) else {
            break None;
        };
        if is_function(parent) {
            break parent
                .field(source, Field::Body)
                .map(|body| StatementPosition {
                    body: body.key(),
                    index: -1,
                    declarator_index: -1,
                });
        }
        if is_statement(parent)
            || delayed_instance_field_value(source, Some(parent), Some(&current))
        {
            break None;
        }
        if parent.babel_type() == "VariableDeclarator" {
            break parents.get(&parent.key()).and_then(|declaration| {
                cached_statement_position(cache, declaration, parents, Some(parent), source)
            });
        }
        current = *parent;
    };
    cache.admit_position();
    cache.reference_initializers.insert(node.key(), position);
    position
}

fn initializer_position<'a>(
    initializer: &Initializer<'a>,
    parents: &NodeParents<'a>,
    reference: bool,
    source: &str,
) -> Option<StatementPosition> {
    initializer
        .entry_body
        .map(|body| StatementPosition {
            body: body.key(),
            index: -1,
            declarator_index: -1,
        })
        .or_else(|| {
            if reference {
                reference_initializer_position(initializer.node, parents, source)
            } else {
                direct_initializer_position(initializer.node, parents, source)
            }
        })
}

fn cached_initializer_position<'a>(
    cache: &mut StatementPositionCache,
    initializer: &Initializer<'a>,
    parents: &NodeParents<'a>,
    reference: bool,
    source: &str,
) -> Option<StatementPosition> {
    initializer
        .entry_body
        .map(|body| StatementPosition {
            body: body.key(),
            index: -1,
            declarator_index: -1,
        })
        .or_else(|| {
            if reference {
                cached_reference_initializer_position(cache, initializer.node, parents, source)
            } else {
                cached_direct_initializer_position(cache, initializer.node, parents, source)
            }
        })
}

fn cached_binding_read_position<'a>(
    cache: &mut StatementPositionCache,
    read: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> BindingReadPosition {
    if let Some(position) = cache.binding_reads.get(&read.key()) {
        return *position;
    }

    let mut current = read;
    let mut path = Vec::with_capacity(8);
    let (mut result, stop) = loop {
        path.push(current);
        let Some(parent) = parents.get(&current.key()).copied() else {
            break (
                BindingReadPosition {
                    position: None,
                    repeating: false,
                },
                true,
            );
        };
        if is_loop(&parent) {
            break (
                BindingReadPosition {
                    position: None,
                    repeating: true,
                },
                true,
            );
        }
        if is_function(&parent)
            || delayed_instance_field_value(source, Some(&parent), Some(&current))
        {
            break (
                BindingReadPosition {
                    position: None,
                    repeating: false,
                },
                true,
            );
        }
        current = parent;
    };
    if !stop {
        return result;
    }
    for node in path.into_iter().rev() {
        let Some(parent) = parents.get(&node.key()).copied() else {
            continue;
        };
        let position = if parent.babel_type() == "VariableDeclarator" {
            parents.get(&parent.key()).and_then(|declaration| {
                (declaration.babel_type() == "VariableDeclaration")
                    .then(|| {
                        cached_statement_position(
                            cache,
                            declaration,
                            parents,
                            Some(&parent),
                            source,
                        )
                    })
                    .flatten()
            })
        } else if is_statement(&parent) && !is_loop(&parent) && !is_function(&parent) {
            cached_statement_position(cache, &parent, parents, None, source)
        } else {
            None
        };
        if position.is_some() {
            result.position = position;
        }
    }
    cache.admit_position();
    cache.binding_reads.insert(read.key(), result);
    result
}

fn initializer_may_retain_entry<'a>(
    initializer_id: InitializerIdentity,
    initializer_node: Node<'a>,
    binding: &BindingState<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let parent = parents.get(&initializer_node.key()).copied();
    let assignment = if initializer_node.babel_type() == "AssignmentExpression" {
        Some(initializer_node)
    } else {
        parent.filter(|node| {
            node.babel_type() == "AssignmentExpression"
                && node
                    .field(source, Field::Right)
                    .is_some_and(|right| right.key() == initializer_node.key())
        })
    };
    let Some(assignment) = assignment else {
        return false;
    };
    if !matches!(assignment.operator(), Some("&&=" | "||=" | "??=")) {
        return false;
    }
    let empty_local = assignment
        .field(source, Field::Right)
        .is_some_and(|right| right.key() == initializer_node.key())
        && binding.kind == super::state::DefinitionKind::Variable
        && !binding.runtime_import
        && binding.initializers.len() == 1
        && binding.initializers[0].record_id == initializer_id.0
        && binding.initializers[0].node.key() == initializer_id.1
        && binding.reference_initializers.is_empty()
        && binding.direct_origins.is_empty()
        && binding
            .definitions
            .iter()
            .any(|definition| definition.kind == super::state::DefinitionKind::Variable)
        && binding.definitions.iter().all(|definition| {
            matches!(
                definition.kind,
                super::state::DefinitionKind::Variable | super::state::DefinitionKind::Assignment
            )
        });
    !empty_local
}

fn retained_initializer_origins<'a>(
    origins: &[OriginFact<'a>],
    binding: &BindingState<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> (HashSet<InitializerIdentity>, bool) {
    let mut latest = None;
    for origin in origins {
        if initializer_may_retain_entry(origin.identity, origin.node, binding, parents, source) {
            continue;
        }
        if let Some(position) = origin.position {
            if latest.is_none_or(|current| precedes(current, position)) {
                latest = Some(position);
            }
        }
    }
    let retained = origins
        .iter()
        .filter(|origin| {
            latest.is_none_or(|latest| {
                origin.position.is_some_and(|position| {
                    (position.index == latest.index
                        && position.declarator_index == latest.declarator_index)
                        || precedes(latest, position)
                })
            })
        })
        .map(|origin| origin.identity)
        .collect();
    (retained, latest.is_some())
}

/// Stable identity for a selector origin.
///
/// Stored initializers use their canonical record identity. Reference-origin
/// wrappers are temporary and intentionally have record ID zero, so they fall
/// back to their AST node key until reference records receive their own
/// canonical identity.
type InitializerIdentity = (usize, NodeKey);

fn initializer_identity<'a>(initializer: &Initializer<'a>) -> InitializerIdentity {
    (initializer.record_id, initializer.node.key())
}

#[derive(Clone, Copy)]
struct OriginFact<'a> {
    identity: InitializerIdentity,
    node: Node<'a>,
    position: Option<StatementPosition>,
}

/// Select binding facts using the cache owned by the current semantic
/// analysis. The cache is valid for the immutable AST and parent map.
pub(crate) fn semantic_binding_at_read_cached<'s, 'a>(
    cache: &mut StatementPositionCache,
    binding: &'s BindingState<'a>,
    read: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> SemanticBindingRead<'s, 'a> {
    let borrowed = |status, has_definite_initializer| SemanticBindingRead {
        status,
        has_definite_initializer,
        binding: Cow::Borrowed(binding),
        selection_changed: false,
    };
    if binding.initializers.is_empty() && binding.reference_initializers.is_empty() {
        return borrowed(BindingReadStatus::Ordered, false);
    }
    let read_position = cached_binding_read_position(cache, read, parents, source);
    let has_definite_initializer = read_position.position.is_some_and(|read_position| {
        binding.initializers.iter().any(|initializer| {
            cached_initializer_position(cache, initializer, parents, false, source)
                .is_some_and(|position| precedes(position, read_position))
                && !initializer_may_retain_entry(
                    initializer_identity(initializer),
                    initializer.node,
                    binding,
                    parents,
                    source,
                )
        })
    });
    if read_position.repeating || read_position.position.is_none() {
        return borrowed(BindingReadStatus::Unresolved, has_definite_initializer);
    }
    let mut origins = Vec::with_capacity(
        binding
            .initializers
            .len()
            .saturating_add(binding.reference_initializers.len()),
    );
    for initializer in &binding.initializers {
        origins.push(OriginFact {
            identity: initializer_identity(initializer),
            node: initializer.node,
            position: cached_initializer_position(cache, initializer, parents, false, source),
        });
    }
    for reference in &binding.reference_initializers {
        origins.push(OriginFact {
            identity: (0, reference.node.key()),
            node: reference.node,
            position: cached_reference_initializer_position(cache, reference.node, parents, source),
        });
    }
    let read_position = read_position.position.expect("checked above");
    let origin_count = origins.len();
    let mut preceding = Vec::with_capacity(origin_count);
    for origin in origins {
        let Some(position) = origin.position else {
            return borrowed(BindingReadStatus::Unresolved, has_definite_initializer);
        };
        if position.body != read_position.body {
            return borrowed(BindingReadStatus::Unresolved, has_definite_initializer);
        }
        if precedes(position, read_position) {
            preceding.push(origin);
        } else if position.index == read_position.index
            && position.declarator_index == read_position.declarator_index
        {
            match expression_evaluation_order(origin.node, read, parents, source) {
                Some(true) => preceding.push(origin),
                _ => {
                    return borrowed(BindingReadStatus::Unresolved, has_definite_initializer);
                }
            }
        }
    }
    let (retained, replaces_entry) =
        retained_initializer_origins(&preceding, binding, parents, source);
    let selection_changed = binding
        .initializers
        .iter()
        .any(|initializer| !retained.contains(&initializer_identity(initializer)))
        || binding
            .reference_initializers
            .iter()
            .any(|initializer| !retained.contains(&(0, initializer.node.key())));
    if !selection_changed {
        return borrowed(
            BindingReadStatus::Ordered,
            has_definite_initializer || replaces_entry,
        );
    }
    let mut selected = binding.clone();
    selected
        .initializers
        .retain(|initializer| retained.contains(&initializer_identity(initializer)));
    selected
        .reference_initializers
        .retain(|initializer| retained.contains(&(0, initializer.node.key())));
    if selection_changed {
        // The TypeScript snapshot spread preserves memberWrites and escapedPaths.
        // Only initializer facts are narrowed here; effect timing is evaluated
        // later against each retained effect's source node.
        selected
            .definitions
            .retain(|definition| definition.kind != super::state::DefinitionKind::Assignment);
    }
    SemanticBindingRead {
        status: BindingReadStatus::Ordered,
        has_definite_initializer: has_definite_initializer || replaces_entry,
        binding: Cow::Owned(selected),
        selection_changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::ast::{AstContext, AstVisitor, traverse};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::state::{self, DefinitionKind, ResolutionMode};
    use oxc_allocator::Allocator;
    use std::ops::ControlFlow;

    struct Nodes<'a> {
        parents: NodeParents<'a>,
        nodes: Vec<Node<'a>>,
    }

    impl<'a> AstVisitor<'a> for Nodes<'a> {
        fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            if let Some(parent) = parent {
                self.parents.insert(node.key(), *parent);
            }
            self.nodes.push(*node);
        }
    }

    fn parse<'a>(allocator: &'a Allocator, source: &'a str) -> (AstContext<'a>, Nodes<'a>) {
        let parsed =
            parse_javascript_analysis_program(allocator, source, Some("timing.js")).expect("parse");
        let context = AstContext::new(parsed.program);
        let mut nodes = Nodes {
            parents: NodeParents::default(),
            nodes: Vec::new(),
        };
        assert!(matches!(
            traverse(context.root(), source, &mut nodes, || {
                ControlFlow::<()>::Continue(())
            }),
            ControlFlow::Continue(())
        ));
        (context, nodes)
    }

    fn first<'a>(nodes: &Nodes<'a>, kind: &str) -> Node<'a> {
        nodes
            .nodes
            .iter()
            .copied()
            .find(|node| node.babel_type() == kind)
            .expect(kind)
    }

    #[test]
    fn top_level_order_handles_same_statement_expression_order() {
        let source = "const value = { child: capture() }; use(value);";
        let allocator = Allocator::default();
        let (context, nodes) = parse(&allocator, source);
        let capture = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| {
                node.babel_type() == "CallExpression"
                    && context.slice(node.span()).starts_with("capture")
            })
            .expect("capture");
        let effect = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| {
                node.babel_type() == "CallExpression"
                    && context.slice(node.span()).starts_with("use")
            })
            .expect("effect");
        assert!(top_level_effect_follows_capture(
            capture,
            Some(effect),
            &nodes.parents,
            source
        ));
    }

    #[test]
    fn top_level_order_preserves_source_order_for_conditionals_and_rejects_loops() {
        for source in [
            "const value = {}; if (flag) value.child = 1;",
            "const value = {}; for (;;) value.child = 1;",
        ] {
            let allocator = Allocator::default();
            let (_context, nodes) = parse(&allocator, source);
            let capture = first(&nodes, "ObjectExpression");
            let effect = nodes
                .nodes
                .iter()
                .copied()
                .find(|node| node.babel_type() == "AssignmentExpression")
                .expect("assignment");
            let follows =
                top_level_effect_follows_capture(capture, Some(effect), &nodes.parents, source);
            assert_eq!(follows, source.starts_with("const value = {}; if"));
        }
    }

    #[test]
    fn top_level_order_rejects_delayed_instance_field_values() {
        let source = "const child = 1; class Box { field = child; }";
        let allocator = Allocator::default();
        let (_context, nodes) = parse(&allocator, source);
        let field = first(&nodes, "ClassProperty");
        let capture = field.field(source, Field::Value).expect("field value");
        assert!(!top_level_effect_follows_capture(
            capture,
            nodes.parents.get(&capture.key()).copied(),
            &nodes.parents,
            source,
        ));
    }

    #[test]
    fn binding_exports_preserve_initializer_and_write_order() {
        let source = "const value = {}; const holder = { child: {} }; value.child = 1; value;";
        let allocator = Allocator::default();
        let (context, nodes) = parse(&allocator, source);
        let ControlFlow::Continue(state) = collect_definitions::<()>(
            context,
            ResolutionMode::Import,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definitions cancelled");
        };
        let binding = state
            .bindings
            .iter()
            .find(|binding| binding.name == "value")
            .expect("value binding");
        let capture = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| {
                node.babel_type() == "ObjectExpression"
                    && state
                        .context
                        .slice(node.span())
                        .starts_with("{ child: {} }")
            })
            .expect("capture");
        let effect = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| node.babel_type() == "AssignmentExpression")
            .expect("effect");
        let read = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| {
                is_identifier(node)
                    && state.context.slice(node.span()) == "value"
                    && state.context.start(node) > state.context.start(&effect)
            })
            .expect("read");
        assert!(semantic_binding_precedes_capture(
            binding,
            capture,
            &state.parents,
            source,
        ));
        assert!(semantic_binding_effect_follows_capture(
            binding,
            capture,
            effect,
            &state.parents,
            source,
        ));
        let mut cache = StatementPositionCache::default();
        let selected =
            semantic_binding_at_read_cached(&mut cache, binding, read, &state.parents, source);
        assert_eq!(selected.status, BindingReadStatus::Ordered);
        assert!(selected.has_definite_initializer);
    }

    #[test]
    fn binding_read_reports_when_later_write_replaces_initializer_selection() {
        let source = "let value = {}; value = {}; value;";
        let allocator = Allocator::default();
        let (context, nodes) = parse(&allocator, source);
        let object_initializers = nodes
            .nodes
            .iter()
            .copied()
            .filter(|node| node.babel_type() == "ObjectExpression")
            .take(2)
            .enumerate()
            .map(|(index, node)| Initializer {
                record_id: index + 1,
                node,
                projection: Vec::new(),
                entry_body: None,
            })
            .collect();
        let binding = BindingState {
            binding_id: "harness:value".to_owned(),
            scope_id: "harness:scope".to_owned(),
            name: "value".to_owned(),
            kind: DefinitionKind::Variable,
            declaration_kinds: Vec::new(),
            mutable: true,
            member_writes: Vec::new(),
            escaped_paths: Vec::new(),
            definitions: vec![
                state::Definition {
                    kind: DefinitionKind::Variable,
                    location: context.range(&context.root()),
                },
                state::Definition {
                    kind: DefinitionKind::Assignment,
                    location: context.range(&context.root()),
                },
            ],
            initializers: object_initializers,
            reference_initializers: Vec::new(),
            direct_origins: Vec::new(),
            runtime_import: false,
        };
        let read = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| {
                is_identifier(node)
                    && context.slice(node.span()) == "value"
                    && context.start(node) >= source.rfind("value;").expect("read") as u32
            })
            .expect("read");

        let mut cache = StatementPositionCache::default();
        let selected =
            semantic_binding_at_read_cached(&mut cache, &binding, read, &nodes.parents, source);

        assert_eq!(selected.status, BindingReadStatus::Ordered);
        assert!(selected.selection_changed);
        assert_eq!(selected.binding.initializers.len(), 1);
        assert_eq!(
            selected.binding.definitions.len(),
            1,
            "assignment metadata must not survive a narrowed read"
        );
        assert_eq!(
            selected.binding.definitions[0].kind,
            DefinitionKind::Variable
        );
    }

    #[test]
    fn initializer_identity_distinguishes_records_sharing_an_ast_node() {
        let source = "let value = {};";
        let allocator = Allocator::default();
        let (context, nodes) = parse(&allocator, source);
        let node = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| node.babel_type() == "ObjectExpression")
            .expect("object initializer");
        let first = Initializer {
            record_id: 1,
            node,
            projection: Vec::new(),
            entry_body: None,
        };
        let second = Initializer {
            record_id: 2,
            ..first.clone()
        };

        assert_eq!(first.node.key(), second.node.key());
        assert_ne!(initializer_identity(&first), initializer_identity(&second));
        assert_eq!(first.record_id, second.record_id - 1);
        assert_eq!(context.slice(node.span()), "{}");
    }

    #[test]
    fn function_body_entry_initializers_precede_body_reads() {
        let source = "function run() { value; } first();";
        let allocator = Allocator::default();
        let (context, nodes) = parse(&allocator, source);
        let initializer = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| context.slice(node.span()) == "first()")
            .expect("initializer");
        let body = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| node.babel_type() == "BlockStatement")
            .expect("function body");
        let read = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| is_identifier(node) && context.slice(node.span()) == "value")
            .expect("body read");
        let binding = BindingState {
            binding_id: "harness:value".to_owned(),
            scope_id: "harness:scope".to_owned(),
            name: "value".to_owned(),
            kind: DefinitionKind::Variable,
            declaration_kinds: Vec::new(),
            mutable: false,
            member_writes: Vec::new(),
            escaped_paths: Vec::new(),
            definitions: Vec::new(),
            initializers: vec![Initializer {
                record_id: 1,
                node: initializer,
                projection: Vec::new(),
                entry_body: Some(body),
            }],
            reference_initializers: Vec::new(),
            direct_origins: Vec::new(),
            runtime_import: false,
        };

        let mut cache = StatementPositionCache::default();
        let selected =
            semantic_binding_at_read_cached(&mut cache, &binding, read, &nodes.parents, source);

        assert_eq!(selected.status, BindingReadStatus::Ordered);
        assert!(selected.has_definite_initializer);
        assert_eq!(selected.binding.initializers.len(), 1);
    }

    #[test]
    fn statement_position_cache_is_scoped_to_one_ast_and_preserves_loop_unknowns() {
        let first_source = "let value = {}; value.child = 1;";
        let first_allocator = Allocator::default();
        let (_first_context, first_nodes) = parse(&first_allocator, first_source);
        let first_mutation = first(&first_nodes, "AssignmentExpression");
        let mut first_cache = StatementPositionCache::default();
        let first_position = cached_direct_mutation_position(
            &mut first_cache,
            first_mutation,
            &first_nodes.parents,
            first_source,
        );
        assert!(first_position.is_some());
        assert_eq!(
            first_position,
            cached_direct_mutation_position(
                &mut first_cache,
                first_mutation,
                &first_nodes.parents,
                first_source,
            )
        );

        let second_source = "let value = {}; if (value) value.child = 1;";
        let second_allocator = Allocator::default();
        let (_second_context, second_nodes) = parse(&second_allocator, second_source);
        let second_mutation = first(&second_nodes, "AssignmentExpression");
        let mut second_cache = StatementPositionCache::default();
        assert!(
            cached_direct_mutation_position(
                &mut second_cache,
                second_mutation,
                &second_nodes.parents,
                second_source,
            )
            .is_none()
        );
    }

    #[test]
    fn body_position_index_matches_legacy_positions_for_nested_declarations() {
        let source = "const first = 1, second = 2; if (flag) { let nested = 3; nested; }";
        let allocator = Allocator::default();
        let (_context, nodes) = parse(&allocator, source);
        let mut cache = StatementPositionCache::default();

        for node in &nodes.nodes {
            if is_statement(node) {
                assert_eq!(
                    cached_statement_position(&mut cache, node, &nodes.parents, None, source),
                    statement_position(node, &nodes.parents, None, source)
                );
            }
            if node.babel_type() != "VariableDeclarator" {
                continue;
            }
            let declaration = nodes
                .parents
                .get(&node.key())
                .copied()
                .expect("declaration parent");
            assert_eq!(
                cached_statement_position(
                    &mut cache,
                    &declaration,
                    &nodes.parents,
                    Some(node),
                    source
                ),
                statement_position(&declaration, &nodes.parents, Some(node), source)
            );
        }
    }

    #[test]
    fn body_position_index_falls_back_when_its_budget_is_exhausted() {
        let source = "const value = 1; value;";
        let allocator = Allocator::default();
        let (_context, nodes) = parse(&allocator, source);
        let statement = nodes
            .nodes
            .iter()
            .copied()
            .find(|node| node.babel_type() == "ExpressionStatement")
            .expect("expression statement");
        let mut cache = StatementPositionCache {
            body_index_entry_limit: Some(0),
            ..StatementPositionCache::default()
        };

        assert_eq!(
            cached_statement_position(&mut cache, &statement, &nodes.parents, None, source),
            statement_position(&statement, &nodes.parents, None, source)
        );
        assert!(cache.body_indexes.is_empty());
        assert!(
            cache.unindexed_bodies.contains(
                &nodes
                    .parents
                    .get(&statement.key())
                    .expect("statement parent")
                    .key()
            )
        );
    }

    #[test]
    fn position_cache_rotates_without_dropping_unresolved_facts_permanently() {
        let source = "const value = 1; for (;;) value;";
        let allocator = Allocator::default();
        let (_context, nodes) = parse(&allocator, source);
        let initializer = first(&nodes, "NumericLiteral");
        let read = nodes
            .nodes
            .iter()
            .copied()
            .rev()
            .find(|node| is_identifier(node) && node.identifier_name() == Some("value"))
            .expect("loop read");

        let mut cache = StatementPositionCache::default();
        let expected_initializer = cached_direct_initializer_position(
            &mut StatementPositionCache::default(),
            initializer,
            &nodes.parents,
            source,
        );
        let actual_initializer =
            cached_direct_initializer_position(&mut cache, initializer, &nodes.parents, source);
        assert_eq!(actual_initializer, expected_initializer);
        assert!(!cache.body_indexes.is_empty());
        let body_index_count = cache.body_indexes.len();

        cache.position_entries = STATEMENT_POSITION_CACHE_ENTRY_LIMIT;
        let expected_read = cached_binding_read_position(
            &mut StatementPositionCache::default(),
            read,
            &nodes.parents,
            source,
        );
        let actual_read = cached_binding_read_position(&mut cache, read, &nodes.parents, source);

        assert_eq!(actual_read, expected_read);
        assert!(actual_read.position.is_none());
        assert!(actual_read.repeating);
        assert_eq!(cache.body_indexes.len(), body_index_count);
        assert!(cache.direct_mutations.is_empty());
        assert!(cache.binding_reads.contains_key(&read.key()));
    }
}

/// Locate an unconditional capture through object and array literal wrappers.
pub fn semantic_capture_position<'a>(
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    let mut cache = StatementPositionCache::default();
    cached_semantic_capture_position(&mut cache, node, parents, source)
}

pub(crate) fn cached_semantic_capture_position<'a>(
    cache: &mut StatementPositionCache,
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    let mut current = node;
    loop {
        if let Some(position) = cached_direct_initializer_position(cache, current, parents, source)
        {
            return Some(position);
        }
        let parent = parents.get(&current.key())?;
        if parent.babel_type() == "ObjectProperty"
            && parent
                .field(source, Field::Value)
                .is_some_and(|value| value.key() == current.key())
            && parent
                .field(source, Field::Key)
                .and_then(|key| static_property_key(source, key, parent.computed()))
                .is_some()
        {
            current = *parent;
        } else if matches!(parent.babel_type(), "ObjectExpression" | "ArrayExpression") {
            current = *parent;
        } else {
            return None;
        }
    }
}

/// A single preceding initializer proves a binding was available at capture.
pub fn semantic_binding_precedes_capture<'a>(
    binding: &BindingState<'a>,
    capture: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let mut cache = StatementPositionCache::default();
    cached_semantic_binding_precedes_capture(&mut cache, binding, capture, parents, source)
}

pub(crate) fn cached_semantic_binding_precedes_capture<'a>(
    cache: &mut StatementPositionCache,
    binding: &BindingState<'a>,
    capture: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    if binding.initializers.len() != 1 {
        return false;
    }
    let Some(initializer) = binding.initializers.first() else {
        return false;
    };
    let Some(source_position) =
        cached_initializer_position(cache, initializer, parents, false, source)
    else {
        return false;
    };
    let Some(capture_position) = cached_semantic_capture_position(cache, capture, parents, source)
    else {
        return false;
    };
    precedes(source_position, capture_position)
}

pub fn semantic_binding_effect_follows_capture<'a>(
    binding: &BindingState<'a>,
    capture: Node<'a>,
    effect: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let mut cache = StatementPositionCache::default();
    cached_semantic_binding_effect_follows_capture(
        &mut cache, binding, capture, effect, parents, source,
    )
}

pub(crate) fn cached_semantic_binding_effect_follows_capture<'a>(
    cache: &mut StatementPositionCache,
    binding: &BindingState<'a>,
    capture: Node<'a>,
    effect: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    if !cached_semantic_binding_precedes_capture(cache, binding, capture, parents, source) {
        return false;
    }
    let Some(captured) = cached_semantic_capture_position(cache, capture, parents, source) else {
        return false;
    };
    let Some(written) = cached_direct_mutation_position(cache, effect, parents, source) else {
        return false;
    };
    precedes(captured, written)
}

pub fn semantic_escape_follows_capture<'a>(
    binding: &BindingState<'a>,
    capture: Node<'a>,
    escape: Option<Node<'a>>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let mut cache = StatementPositionCache::default();
    cached_semantic_escape_follows_capture(&mut cache, binding, capture, escape, parents, source)
}

pub(crate) fn cached_semantic_escape_follows_capture<'a>(
    cache: &mut StatementPositionCache,
    binding: &BindingState<'a>,
    capture: Node<'a>,
    escape: Option<Node<'a>>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let Some(escape) = escape else { return false };
    if binding.initializers.len() != 1
        || !cached_semantic_binding_precedes_capture(cache, binding, capture, parents, source)
    {
        return false;
    }
    let origin = unwrapped(source, binding.initializers[0].node);
    if !matches!(
        origin.babel_type(),
        "ObjectExpression"
            | "ArrayExpression"
            | "Identifier"
            | "IdentifierName"
            | "IdentifierReference"
    ) && !is_member(&origin)
    {
        return false;
    }
    let Some(capture_position) = cached_semantic_capture_position(cache, capture, parents, source)
    else {
        return false;
    };
    let Some(escape_position) = cached_direct_mutation_position(cache, escape, parents, source)
    else {
        return false;
    };
    precedes(capture_position, escape_position)
}

/// Determine whether a top-level effect follows a capture in source order.
pub fn top_level_effect_follows_capture<'a>(
    capture: Node<'a>,
    effect: Option<Node<'a>>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let mut cache = StatementPositionCache::default();
    cached_top_level_effect_follows_capture(&mut cache, capture, effect, parents, source)
}

pub(crate) fn cached_top_level_effect_follows_capture<'a>(
    cache: &mut StatementPositionCache,
    capture: Node<'a>,
    effect: Option<Node<'a>>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let Some(effect) = effect else { return false };
    let before = cached_top_level_position(cache, capture, parents, source);
    let after = cached_top_level_position(cache, effect, parents, source);
    match (before, after) {
        (Some(before), Some(after)) if before.body == after.body => {
            if precedes(before, after) {
                true
            } else if before.index == after.index
                && before.declarator_index == after.declarator_index
            {
                expression_evaluation_order(capture, effect, parents, source) == Some(true)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn cached_top_level_position<'a>(
    cache: &mut StatementPositionCache,
    node: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<StatementPosition> {
    let mut selected = None;
    let mut declarator = None;
    let mut child = None;
    let mut current = Some(node);
    while let Some(node) = current {
        if is_function(&node) || is_loop(&node) {
            return None;
        }
        if delayed_instance_field_value(source, Some(&node), child.as_ref()) {
            return None;
        }
        if node.babel_type() == "VariableDeclarator" {
            declarator = Some(node);
        }
        if is_statement(&node) {
            selected =
                cached_statement_position(cache, &node, parents, declarator.as_ref(), source);
        }
        if node.babel_type() == "Program" {
            return selected;
        }
        child = Some(node);
        current = parents.get(&node.key()).copied();
    }
    None
}

/// Classify an effect relative to a read site. Unknown remains unknown.
pub fn effect_timing<'a>(
    site: Node<'a>,
    effect: Option<Node<'a>>,
    state: &SemanticState<'a>,
    source: &str,
) -> EffectTiming {
    cached_effect_timing(
        &mut state.statement_position_cache.borrow_mut(),
        site,
        effect,
        state,
        source,
    )
}

pub(crate) fn cached_effect_timing<'a>(
    cache: &mut StatementPositionCache,
    site: Node<'a>,
    effect: Option<Node<'a>>,
    state: &SemanticState<'a>,
    source: &str,
) -> EffectTiming {
    let Some(effect) = effect else {
        return EffectTiming::Unknown;
    };
    if site.key() == effect.key()
        && matches!(
            site.babel_type(),
            "CallExpression" | "OptionalCallExpression" | "NewExpression"
        )
    {
        return EffectTiming::After;
    }
    if let Some(loop_node) = enclosing_iteration(effect, &state.parents) {
        match iteration_cardinality(source, &loop_node, state.prototype_enumeration_may_affect) {
            IterationCardinality::Empty => return EffectTiming::After,
            IterationCardinality::Nonempty => {
                let loop_parent = state.parents.get(&loop_node.key()).copied();
                let crosses_function = |node: Node<'a>| {
                    let mut current = Some(node);
                    while let Some(current_node) = current {
                        if is_function(&current_node) {
                            return true;
                        }
                        current = state.parents.get(&current_node.key()).copied();
                    }
                    false
                };
                if loop_parent.is_some_and(|parent| parent.key() == state.program.key())
                    && !crosses_function(site)
                {
                    let loop_start = state.context.start(&loop_node);
                    let loop_end = state.context.end(&loop_node);
                    let site_start = state.context.start(&site);
                    if site_start > loop_end {
                        return EffectTiming::Before;
                    }
                    if site_start < loop_start {
                        return EffectTiming::After;
                    }
                }
            }
            IterationCardinality::Unknown => {}
        }
    }
    let follows_site =
        cached_semantic_effect_follows_reference(cache, site, effect, &state.parents, source);
    let follows_effect =
        cached_semantic_effect_follows_reference(cache, effect, site, &state.parents, source);
    match (follows_site, follows_effect) {
        (true, false) => EffectTiming::After,
        (false, true) => EffectTiming::Before,
        _ => EffectTiming::Unknown,
    }
}

fn enclosing_iteration<'a>(node: Node<'a>, parents: &NodeParents<'a>) -> Option<Node<'a>> {
    let mut current = Some(node);
    while let Some(node) = current {
        if matches!(node.babel_type(), "ForInStatement" | "ForOfStatement") {
            return Some(node);
        }
        if is_function(&node) {
            return None;
        }
        current = parents.get(&node.key()).copied();
    }
    None
}

pub fn semantic_effect_follows_reference<'a>(
    reference: Node<'a>,
    effect: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    let mut cache = StatementPositionCache::default();
    cached_semantic_effect_follows_reference(&mut cache, reference, effect, parents, source)
}

fn cached_semantic_effect_follows_reference<'a>(
    cache: &mut StatementPositionCache,
    reference: Node<'a>,
    effect: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> bool {
    if reference.key() == effect.key() {
        return false;
    }
    let mut current = reference;
    let mut child = None;
    while current.key() != effect.key() {
        if is_function(&current) {
            break;
        }
        child = Some(current);
        let Some(parent) = parents.get(&current.key()).copied() else {
            break;
        };
        current = parent;
    }
    let loop_input = matches!(effect.babel_type(), "ForInStatement" | "ForOfStatement")
        && child.is_some_and(|child| {
            effect
                .field(source, Field::Right)
                .is_some_and(|right| right.key() == child.key())
        });

    let mut once = Some(current);
    child = None;
    while let Some(node) = once {
        let initial_loop_input = (node.babel_type() == "ForStatement"
            && child.is_some_and(|child| {
                node.field(source, Field::Init)
                    .is_some_and(|init| init.key() == child.key())
            }))
            || matches!(node.babel_type(), "ForInStatement" | "ForOfStatement")
                && child.is_some_and(|child| {
                    node.field(source, Field::Right)
                        .is_some_and(|right| right.key() == child.key())
                })
            || (node.key() == effect.key() && loop_input);
        if is_function(&node)
            || (is_loop(&node) && !initial_loop_input)
            || delayed_instance_field_value(source, Some(&node), child.as_ref())
        {
            break;
        }
        child = Some(node);
        once = parents.get(&node.key()).copied();
    }
    (current.key() == effect.key()
        && once.is_none()
        && (matches!(
            effect.babel_type(),
            "AssignmentExpression"
                | "UpdateExpression"
                | "VariableDeclarator"
                | "CallExpression"
                | "OptionalCallExpression"
                | "NewExpression"
        ) || loop_input))
        || cached_top_level_effect_follows_capture(cache, reference, Some(effect), parents, source)
}

/// Keep only initializer origins proven to precede a mutation.
pub fn mutation_initializers<'a>(
    binding: &BindingState<'a>,
    mutation: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> BindingState<'a> {
    let Some((initializers, reference_initializers, replaces_entry)) =
        selected_initializer_origins(binding, mutation, parents, source)
    else {
        return binding.clone();
    };

    let mut result = binding.clone();
    if replaces_entry {
        result.direct_origins.clear();
    }
    result.initializers = initializers;
    result.reference_initializers = reference_initializers;
    result
}

/// Select mutation-visible origins without cloning unrelated binding state.
/// Member mutation collection only needs these two origin lists, so keeping
/// this projection separate avoids copying definitions and effect history.
pub fn selected_initializer_origins<'a>(
    binding: &BindingState<'a>,
    mutation: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<(Vec<Initializer<'a>>, Vec<ReferenceInitializer<'a>>, bool)> {
    let mut cache = StatementPositionCache::default();
    selected_initializer_origins_cached(&mut cache, binding, mutation, parents, source)
}

/// Cached form used by the member-mutation collector for one complete
/// analysis. The public wrapper above preserves the existing call contract.
pub fn selected_initializer_origins_cached<'a>(
    cache: &mut StatementPositionCache,
    binding: &BindingState<'a>,
    mutation: Node<'a>,
    parents: &NodeParents<'a>,
    source: &str,
) -> Option<(Vec<Initializer<'a>>, Vec<ReferenceInitializer<'a>>, bool)> {
    let Some(mutation_position) = cached_direct_mutation_position(cache, mutation, parents, source)
        .or_else(|| cached_reference_initializer_position(cache, mutation, parents, source))
    else {
        return None;
    };
    let mut origins = Vec::new();
    for initializer in &binding.initializers {
        origins.push(OriginFact {
            identity: initializer_identity(initializer),
            node: initializer.node,
            position: cached_initializer_position(cache, initializer, parents, false, source),
        });
    }
    for initializer in &binding.reference_initializers {
        origins.push(OriginFact {
            identity: (0, initializer.node.key()),
            node: initializer.node,
            position: cached_reference_initializer_position(
                cache,
                initializer.node,
                parents,
                source,
            ),
        });
    }
    for origin in &origins {
        let Some(position) = origin.position else {
            return None;
        };
        if position.body != mutation_position.body || !precedes(position, mutation_position) {
            return None;
        }
    }
    let (retained, replaces_entry) =
        retained_initializer_origins(&origins, binding, parents, source);
    let initializers = binding
        .initializers
        .iter()
        .filter(|initializer| retained.contains(&initializer_identity(initializer)))
        .cloned()
        .collect();
    let reference_initializers = binding
        .reference_initializers
        .iter()
        .filter(|initializer| retained.contains(&(0, initializer.node.key())))
        .cloned()
        .collect();
    Some((initializers, reference_initializers, replaces_entry))
}
