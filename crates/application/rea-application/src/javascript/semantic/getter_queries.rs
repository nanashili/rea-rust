//! Bounded, memoized getter queries.
//!
//! This module owns query scheduling and reference identity.  Getter result
//! interpretation belongs to `getter_results`; callers provide the root and
//! expansion callbacks so this layer never evaluates JavaScript expressions.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::javascript::ast::{Node, NodeKey};

use super::property_paths::PropertyPath;
use super::state::SemanticState;
use super::value_types::ResourceLimit;

/// One object reference produced while following a getter or object member.
#[derive(Clone, Debug)]
pub struct SemanticObjectReference<'a> {
    pub node: Node<'a>,
    pub path: PropertyPath,
    pub escapes: bool,
    pub widened_getter_result: bool,
    pub owner_initializer: Option<Node<'a>>,
}

/// The getter and object that define one invocation.
#[derive(Clone, Copy, Debug)]
pub struct GetterInvocation<'a> {
    pub getter: Node<'a>,
    pub owner: Node<'a>,
    pub receiver: Option<Node<'a>>,
}

impl<'a> GetterInvocation<'a> {
    pub fn receiver(&self) -> Node<'a> {
        self.receiver.unwrap_or(self.owner)
    }
}

#[derive(Clone, Copy, Debug)]
struct GetterAncestor {
    getter: NodeKey,
    receiver: NodeKey,
    path_length: usize,
}

/// A queued getter result expansion.
#[derive(Clone, Debug)]
pub struct GetterQueryJob<'a> {
    pub invocation: GetterInvocation<'a>,
    pub path: PropertyPath,
    pub escapes: bool,
    ancestry: Vec<GetterAncestor>,
}

impl GetterQueryJob<'_> {
    /// The ancestry is intentionally opaque to result walkers; it is only
    /// used by [`SemanticGetterQuery::schedule`] to detect growing cycles.
    pub fn ancestry_len(&self) -> usize {
        self.ancestry.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MemoKey {
    getter: NodeKey,
    receiver: NodeKey,
    path: String,
    escapes: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ReferenceKey {
    node: NodeKey,
    path: String,
    owner_id: Option<usize>,
    escapes: bool,
    widened_getter_result: bool,
}

/// An insertion-ordered set of references with stable owner allocation IDs.
#[derive(Default)]
pub struct SemanticObjectReferenceSet<'a> {
    node_order: Vec<NodeKey>,
    references: HashMap<NodeKey, Vec<SemanticObjectReference<'a>>>,
    identities: HashMap<ReferenceKey, (NodeKey, usize)>,
    owner_ids: HashMap<NodeKey, usize>,
}

impl<'a> SemanticObjectReferenceSet<'a> {
    pub fn add(&mut self, reference: SemanticObjectReference<'a>) -> bool {
        let owner_id = reference.owner_initializer.map(|owner| {
            let next = self.owner_ids.len();
            *self.owner_ids.entry(owner.key()).or_insert(next)
        });
        let path = serde_json::to_string(&reference.path).expect("property path is serializable");
        let identity = ReferenceKey {
            node: reference.node.key(),
            path,
            owner_id,
            escapes: reference.escapes,
            widened_getter_result: reference.widened_getter_result,
        };
        if let Some((node, index)) = self.identities.get(&identity).copied() {
            self.references
                .get_mut(&node)
                .expect("reference identity has a node bucket")[index] = reference;
            return false;
        }
        let node = reference.node.key();
        if !self.references.contains_key(&node) {
            self.node_order.push(node);
            self.references.insert(node, Vec::new());
        }
        let entries = self
            .references
            .get_mut(&node)
            .expect("node bucket inserted");
        let index = entries.len();
        entries.push(reference);
        self.identities.insert(identity, (node, index));
        true
    }

    pub fn clear(&mut self) {
        self.node_order.clear();
        self.references.clear();
        self.identities.clear();
        self.owner_ids.clear();
    }

    pub fn values(&self) -> Vec<SemanticObjectReference<'a>> {
        self.node_order
            .iter()
            .flat_map(|node| self.references.get(node).into_iter().flatten().cloned())
            .collect()
    }

    pub fn into_values(self) -> Vec<SemanticObjectReference<'a>> {
        let mut references = self.references;
        let mut values = Vec::new();
        for node in self.node_order {
            if let Some(mut entries) = references.remove(&node) {
                values.append(&mut entries);
            }
        }
        values
    }
}

/// Bounded getter expansion with a conservative retry after widening.
pub struct SemanticGetterQuery<'state, 'ast> {
    limits: &'state RefCell<Vec<ResourceLimit>>,
    memo: HashSet<MemoKey>,
    references: SemanticObjectReferenceSet<'ast>,
    pending: VecDeque<GetterQueryJob<'ast>>,
    current: Option<GetterQueryJob<'ast>>,
    fallback: bool,
    limited: bool,
    visits: usize,
}

impl<'state, 'ast> SemanticGetterQuery<'state, 'ast> {
    /// Build a query that records resource limits in the owning state.
    pub fn new(state: &'state SemanticState<'ast>) -> Self {
        Self::with_limits(&state.getter_resource_limits)
    }

    /// Build a query for callers that own a compatible limit ledger.
    pub fn with_limits(limits: &'state RefCell<Vec<ResourceLimit>>) -> Self {
        Self {
            limits,
            memo: HashSet::new(),
            references: SemanticObjectReferenceSet::default(),
            pending: VecDeque::new(),
            current: None,
            fallback: false,
            limited: false,
            visits: 0,
        }
    }

    pub fn widening(&self) -> bool {
        self.fallback
    }

    pub fn current_job(&self) -> Option<&GetterQueryJob<'ast>> {
        self.current.as_ref()
    }

    /// Reserve one result expansion or mark the query for conservative retry.
    pub fn reserve_result(&mut self) -> bool {
        if self.limited {
            return false;
        }
        if !self.fallback && self.visits >= super::limits::SEMANTIC_GETTER_EXPANSION_LIMIT {
            self.limited = true;
            return false;
        }
        self.visits += 1;
        true
    }

    pub fn retain(&mut self, mut reference: SemanticObjectReference<'ast>, escapes: bool) {
        reference.escapes |= escapes;
        reference.widened_getter_result |= self.fallback && self.current.is_some();
        self.references.add(reference);
    }

    /// Schedule a getter invocation unless it is memoized or a growing cycle.
    pub fn schedule(
        &mut self,
        invocation: GetterInvocation<'ast>,
        path: PropertyPath,
        escaped: bool,
    ) {
        if self.limited {
            return;
        }

        let current_escapes = self.current.as_ref().is_some_and(|job| job.escapes);
        let escapes = escaped || self.fallback || current_escapes;
        let selection = if self.fallback { Vec::new() } else { path };

        let receiver = invocation.receiver();
        let ancestor = GetterAncestor {
            getter: invocation.getter.key(),
            receiver: receiver.key(),
            path_length: selection.len(),
        };
        if self.grows(&ancestor) {
            self.limited = true;
            return;
        }

        let path_key = serde_json::to_string(&selection).expect("property path is serializable");
        let memo_key = MemoKey {
            getter: invocation.getter.key(),
            receiver: receiver.key(),
            path: path_key,
            escapes,
        };
        if self.memo.contains(&memo_key) {
            return;
        }
        if !self.reserve_result() {
            return;
        }
        self.memo.insert(memo_key);

        let mut ancestry = self
            .current
            .as_ref()
            .map_or_else(Vec::new, |job| job.ancestry.clone());
        if let Some(current) = self.current.as_ref() {
            ancestry.push(GetterAncestor {
                getter: current.invocation.getter.key(),
                receiver: current.invocation.receiver().key(),
                path_length: current.path.len(),
            });
        }
        self.pending.push_back(GetterQueryJob {
            invocation,
            path: selection,
            escapes,
            ancestry,
        });
    }

    fn grows(&self, candidate: &GetterAncestor) -> bool {
        self.current.as_ref().is_some_and(|job| {
            let current = GetterAncestor {
                getter: job.invocation.getter.key(),
                receiver: job.invocation.receiver().key(),
                path_length: job.path.len(),
            };
            job.ancestry
                .iter()
                .chain(std::iter::once(&current))
                .any(|ancestor| {
                    ancestor.getter == candidate.getter
                        && ancestor.receiver == candidate.receiver
                        && ancestor.path_length < candidate.path_length
                })
        })
    }

    fn collect<Root, Expand>(&mut self, mut root: Root, mut expand: Expand)
    where
        Root: FnMut(&mut Self),
        Expand: FnMut(&GetterQueryJob<'ast>, &mut Self),
    {
        root(self);
        while !self.limited {
            let Some(job) = self.pending.pop_front() else {
                break;
            };
            self.current = Some(job);
            let current = self.current.clone().expect("current job set");
            expand(&current, self);
        }
        self.current = None;
    }

    /// Run once, retrying from the root with a wildcard path after a limit.
    pub fn run<Root, Expand>(
        &mut self,
        mut root: Root,
        mut expand: Expand,
    ) -> Vec<SemanticObjectReference<'ast>>
    where
        Root: FnMut(&mut Self),
        Expand: FnMut(&GetterQueryJob<'ast>, &mut Self),
    {
        self.collect(&mut root, &mut expand);
        if self.limited {
            let mut limits = self.limits.borrow_mut();
            if !limits.contains(&ResourceLimit::GetterExpansion) {
                limits.push(ResourceLimit::GetterExpansion);
            }
            drop(limits);

            self.fallback = true;
            self.limited = false;
            self.memo.clear();
            self.references.clear();
            self.pending.clear();
            self.current = None;
            self.collect(&mut root, &mut expand);
        }
        self.references.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::ast::{AstContext, AstVisitor, traverse};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::property_paths::PropertyPathKey;
    use oxc_allocator::Allocator;
    use std::ops::ControlFlow;

    struct Nodes<'a>(Vec<Node<'a>>);

    impl<'a> AstVisitor<'a> for Nodes<'a> {
        fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            self.0.push(*node);
        }
    }

    fn parsed_nodes<'a>(allocator: &'a Allocator, source: &'a str) -> Vec<Node<'a>> {
        let parsed = parse_javascript_analysis_program(allocator, source, Some("getter-query.js"))
            .expect("parse");
        let context = AstContext::new(parsed.program);
        let mut nodes = Nodes(Vec::new());
        assert!(matches!(
            traverse(context.root(), source, &mut nodes, || {
                ControlFlow::<()>::Continue(())
            }),
            ControlFlow::Continue(())
        ));
        nodes.0
    }

    fn invocation<'a>(node: Node<'a>) -> GetterInvocation<'a> {
        GetterInvocation {
            getter: node,
            owner: node,
            receiver: Some(node),
        }
    }

    fn reference<'a>(node: Node<'a>, path: &str) -> SemanticObjectReference<'a> {
        SemanticObjectReference {
            node,
            path: vec![PropertyPathKey::String(path.into())],
            escapes: false,
            widened_getter_result: false,
            owner_initializer: None,
        }
    }

    #[test]
    fn references_deduplicate_by_owner_allocation_and_escape_state() {
        let allocator = Allocator::default();
        let nodes = parsed_nodes(&allocator, "const value = {}; const other = {};");
        let object = nodes
            .iter()
            .copied()
            .find(|node| node.babel_type() == "ObjectExpression")
            .expect("object");
        let other = nodes
            .iter()
            .copied()
            .rev()
            .find(|node| node.babel_type() == "ObjectExpression")
            .expect("other object");
        let mut set = SemanticObjectReferenceSet::default();
        let reference = |owner_initializer, escapes| SemanticObjectReference {
            node: object,
            path: vec![],
            escapes,
            widened_getter_result: false,
            owner_initializer,
        };

        assert!(set.add(reference(Some(object), false)));
        assert!(!set.add(reference(Some(object), false)));
        assert!(set.add(reference(Some(object), true)));
        assert!(set.add(reference(Some(other), false)));
        assert_eq!(set.values().len(), 3);
    }

    #[test]
    fn references_group_by_first_node_then_keep_inner_insertion_order() {
        let allocator = Allocator::default();
        let nodes = parsed_nodes(&allocator, "const first = {}; const second = {};");
        let mut objects = nodes
            .iter()
            .copied()
            .filter(|node| node.babel_type() == "ObjectExpression");
        let first = objects.next().expect("first object");
        let second = objects.next().expect("second object");
        let mut set = SemanticObjectReferenceSet::default();
        set.add(reference(first, "first-a"));
        set.add(reference(second, "second-a"));
        set.add(reference(first, "first-b"));

        let values = set.values();
        assert_eq!(
            values
                .iter()
                .map(|reference| reference.node.key())
                .collect::<Vec<_>>(),
            vec![first.key(), first.key(), second.key()]
        );
    }

    #[test]
    fn finite_same_path_cycle_is_memoized_without_widening() {
        let allocator = Allocator::default();
        let node = parsed_nodes(&allocator, "const value = {};")[0];
        let limits = RefCell::new(Vec::new());
        let mut query = SemanticGetterQuery::with_limits(&limits);
        let invocation = invocation(node);
        let result = query.run(
            |query| query.schedule(invocation, vec![], false),
            |job, query| query.schedule(job.invocation, job.path.clone(), job.escapes),
        );

        assert!(result.is_empty());
        assert!(limits.borrow().is_empty());
    }

    #[test]
    fn duplicate_scheduling_does_not_consume_the_visit_budget() {
        let allocator = Allocator::default();
        let node = parsed_nodes(&allocator, "const value = {};")[0];
        let limits = RefCell::new(Vec::new());
        let mut query = SemanticGetterQuery::with_limits(&limits);
        let invocation = invocation(node);
        let result = query.run(
            |query| {
                for _ in 0..513 {
                    query.schedule(invocation, vec![], false);
                }
                for index in 0..511 {
                    query.schedule(
                        invocation,
                        vec![PropertyPathKey::String(index.to_string().into())],
                        false,
                    );
                }
            },
            |_job, _query| {},
        );

        assert!(result.is_empty());
        assert!(limits.borrow().is_empty());
    }

    #[test]
    fn the_boundary_job_triggers_widening_after_512_unique_schedules() {
        let allocator = Allocator::default();
        let node = parsed_nodes(&allocator, "const value = {};")[0];
        let limits = RefCell::new(Vec::new());
        let mut query = SemanticGetterQuery::with_limits(&limits);
        let invocation = invocation(node);
        let result = query.run(
            |query| {
                for index in 0..512 {
                    query.schedule(
                        invocation,
                        vec![PropertyPathKey::String(index.to_string().into())],
                        false,
                    );
                }
                query.schedule(
                    invocation,
                    vec![PropertyPathKey::String("boundary".into())],
                    false,
                );
            },
            |_job, _query| {},
        );

        assert!(result.is_empty());
        assert!(query.widening());
        assert_eq!(&*limits.borrow(), &[ResourceLimit::GetterExpansion]);
    }

    #[test]
    fn growing_cycle_retries_with_wildcard_and_records_typed_limit() {
        let allocator = Allocator::default();
        let node = parsed_nodes(&allocator, "const value = {};")[0];
        let limits = RefCell::new(Vec::new());
        let mut query = SemanticGetterQuery::with_limits(&limits);
        let invocation = invocation(node);
        let result = query.run(
            |query| {
                query.schedule(
                    invocation,
                    vec![super::super::property_paths::PropertyPathKey::String(
                        "a".into(),
                    )],
                    false,
                )
            },
            |job, query| {
                let mut path = job.path.clone();
                path.push(super::super::property_paths::PropertyPathKey::String(
                    "b".into(),
                ));
                query.schedule(job.invocation, path, false);
            },
        );

        assert!(result.is_empty());
        assert_eq!(&*limits.borrow(), &[ResourceLimit::GetterExpansion]);
    }
}
