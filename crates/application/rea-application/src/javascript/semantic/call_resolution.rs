//! Local call-target resolution for the semantic JavaScript state.
//!
//! This is the Rust counterpart of `javascriptSemanticCallResolution.ts`.
//! Resolution is deliberately local: dynamic properties, imported callables,
//! and projected values remain unresolved rather than being guessed.

use std::collections::{HashMap, HashSet};

use crate::javascript::ast::{Field, Node, NodeKey};

use super::ast_values::{runtime_function_parameters, unwrapped};
use super::mutation_initializers::semantic_binding_at_read;
use super::projection::{SemanticCallable, callable_id_for_node};
use super::state::{BindingIndex, DefinitionKind, SemanticState};

/// Resolution of one call target within the currently analyzed source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCallableResolution {
    pub callable_ids: Vec<String>,
    pub complete: bool,
    pub reason: String,
    /// A cycle cut depends on the active alias path and cannot be memoized.
    pub cycle_dependent: bool,
}

/// Identity of one initializer in a binding's source-ordered initializer list.
pub type InitializerIdentity = usize;

struct ResolutionContext<'s, 'a> {
    state: &'s SemanticState<'a>,
    callable_nodes: &'s HashMap<String, Node<'a>>,
    seen_initializers: HashSet<InitializerIdentity>,
    seen_bindings: HashSet<String>,
    binding_cache: &'s mut HashMap<NodeKey, LocalCallableResolution>,
}

/// Collect the callable nodes needed by [`resolve_local_callables`].
pub fn callable_nodes<'a>(state: &SemanticState<'a>) -> HashMap<String, Node<'a>> {
    let mut nodes = HashMap::new();
    let mut pending = vec![state.program];

    while let Some(node) = pending.pop() {
        if let Some(callable_id) = callable_id_for_node(&state.context, &node) {
            nodes.insert(callable_id, node);
        }
        pending.extend(node.children(state.source).into_iter().rev());
    }

    nodes
}

/// Resolve local callable candidates without following dynamic properties.
pub fn resolve_local_callables<'a>(
    node: Node<'a>,
    state: &SemanticState<'a>,
    callable_nodes: &HashMap<String, Node<'a>>,
    seen_initializers: &HashSet<InitializerIdentity>,
    binding_cache: &mut HashMap<NodeKey, LocalCallableResolution>,
) -> LocalCallableResolution {
    let mut context = ResolutionContext {
        state,
        callable_nodes,
        seen_initializers: seen_initializers.clone(),
        seen_bindings: HashSet::new(),
        binding_cache,
    };
    context.resolve(node)
}

/// Resolve every unconditional initializer owned by one lexical binding.
/// Module-link resolution uses this entry point so it shares the same
/// assignment, alias, cycle, and projection rules as ordinary call sites.
pub fn resolve_local_callable_binding<'a>(
    binding: BindingIndex,
    state: &SemanticState<'a>,
    callable_nodes: &HashMap<String, Node<'a>>,
    binding_cache: &mut HashMap<NodeKey, LocalCallableResolution>,
) -> LocalCallableResolution {
    let mut context = ResolutionContext {
        state,
        callable_nodes,
        seen_initializers: HashSet::new(),
        seen_bindings: HashSet::new(),
        binding_cache,
    };
    context.resolve_binding_callables(state.binding(binding))
}

impl<'s, 'a> ResolutionContext<'s, 'a> {
    fn resolve(&mut self, node: Node<'a>) -> LocalCallableResolution {
        let unwrapped = unwrapped(self.state.source, node);
        if unwrapped.key() != node.key() {
            return self.resolve(unwrapped);
        }

        if let Some(callable_id) = callable_id_for_node(&self.state.context, &node)
            && self.callable_nodes.contains_key(&callable_id)
        {
            return LocalCallableResolution {
                callable_ids: vec![callable_id],
                complete: true,
                reason: "Direct local callable.".to_owned(),
                cycle_dependent: false,
            };
        }

        if node.babel_type() == "Identifier" {
            return self.resolve_identifier(node);
        }

        match node.babel_type() {
            "ConditionalExpression" | "LogicalExpression" => {
                let (left, right) = if node.babel_type() == "ConditionalExpression" {
                    (
                        node.field(self.state.source, Field::Consequent),
                        node.field(self.state.source, Field::Alternate),
                    )
                } else {
                    (
                        node.field(self.state.source, Field::Left),
                        node.field(self.state.source, Field::Right),
                    )
                };
                match (left, right) {
                    (Some(left), Some(right)) => self.resolve_alternatives(left, right),
                    _ => self.unsupported(node),
                }
            }
            _ => self.unsupported(node),
        }
    }

    fn resolve_identifier(&mut self, node: Node<'a>) -> LocalCallableResolution {
        if let Some(cached) = self.binding_cache.get(&node.key()) {
            return cached.clone();
        }

        let Some(name) = node.identifier_name() else {
            return self.unresolved("Unresolved call target.".to_owned());
        };
        let Some(binding_index) = self.state.resolve_binding(&node, name) else {
            return self.unresolved(format!("Unresolved call target {name}."));
        };
        let binding = self.state.binding(binding_index);
        let read = semantic_binding_at_read(binding, node, &self.state.parents, self.state.source);
        let selects_all = !read.selection_changed;

        let candidates = if selects_all {
            let inserted = self.seen_bindings.insert(read.binding.binding_id.clone());
            let candidates = if !inserted {
                LocalCallableResolution {
                    callable_ids: Vec::new(),
                    complete: false,
                    reason: format!("Call target initializer cycle at {}.", read.binding.name),
                    cycle_dependent: true,
                }
            } else {
                self.resolve_binding_callables(&read.binding)
            };
            if inserted {
                self.seen_bindings.remove(&read.binding.binding_id);
            }
            candidates
        } else {
            // A narrowed read inherits the active alias path.  Clearing the
            // path here would hide a cycle that crosses a temporal selection.
            self.resolve_binding_callables(&read.binding)
        };

        let covered =
            read.has_definite_initializer || self.state.stable_initializer(binding_index).is_some();
        let resolution = if candidates.complete && !covered {
            LocalCallableResolution {
                callable_ids: candidates.callable_ids,
                complete: false,
                reason: format!(
                    "Call target {} may retain an incoming value or an unordered assignment.",
                    read.binding.name
                ),
                cycle_dependent: candidates.cycle_dependent,
            }
        } else {
            candidates
        };

        if !resolution.cycle_dependent {
            self.binding_cache.insert(node.key(), resolution.clone());
        }
        resolution
    }

    fn resolve_binding_callables(
        &mut self,
        binding: &super::state::BindingState<'a>,
    ) -> LocalCallableResolution {
        if binding.initializers.is_empty() {
            let reason = if binding.kind == DefinitionKind::Import {
                format!(
                    "Call target {} is imported from outside this source.",
                    binding.name
                )
            } else {
                format!("Call target {} has no local initializer.", binding.name)
            };
            return self.unresolved(reason);
        }

        let initializers = binding.initializers.clone();
        let mut candidates = Vec::with_capacity(initializers.len());
        for initializer in &initializers {
            let key = initializer.record_id;
            debug_assert!(
                key != 0,
                "stored binding initializers must have canonical record identities"
            );
            if self.seen_initializers.contains(&key) {
                candidates.push(LocalCallableResolution {
                    callable_ids: Vec::new(),
                    complete: false,
                    reason: format!("Call target initializer cycle at {}.", binding.name),
                    cycle_dependent: true,
                });
                continue;
            }
            if !initializer.projection.is_empty() {
                candidates.push(LocalCallableResolution {
                    callable_ids: Vec::new(),
                    complete: false,
                    reason: format!("Projected call target {} is unresolved.", binding.name),
                    cycle_dependent: false,
                });
                continue;
            }

            self.seen_initializers.insert(key);
            candidates.push(self.resolve(initializer.node));
            self.seen_initializers.remove(&key);
        }

        let callable_ids = unique_callable_ids(
            candidates
                .iter()
                .flat_map(|candidate| candidate.callable_ids.iter().cloned()),
        );
        let complete = candidates.iter().all(|candidate| candidate.complete);
        let reason = if callable_ids.len() == 1 && complete {
            "Unique local callable target.".to_owned()
        } else {
            format!(
                "Call target {} has ambiguous or unsupported assignments.",
                binding.name
            )
        };
        LocalCallableResolution {
            callable_ids,
            complete,
            reason,
            cycle_dependent: candidates.iter().any(|candidate| candidate.cycle_dependent),
        }
    }

    fn resolve_alternatives(&mut self, left: Node<'a>, right: Node<'a>) -> LocalCallableResolution {
        let left = self.resolve(left);
        let right = self.resolve(right);
        let callable_ids = unique_callable_ids(
            left.callable_ids
                .iter()
                .chain(right.callable_ids.iter())
                .cloned(),
        );
        LocalCallableResolution {
            callable_ids,
            complete: left.complete && right.complete,
            reason: "Conditional or logical call target has multiple candidates.".to_owned(),
            cycle_dependent: left.cycle_dependent || right.cycle_dependent,
        }
    }

    fn unsupported(&self, node: Node<'a>) -> LocalCallableResolution {
        self.unresolved(format!("Unsupported {} call target.", node.babel_type()))
    }

    fn unresolved(&self, reason: String) -> LocalCallableResolution {
        LocalCallableResolution {
            callable_ids: Vec::new(),
            complete: false,
            reason,
            cycle_dependent: false,
        }
    }
}

/// Find all bindings introduced by one positional parameter pattern.
pub fn parameter_bindings<'a>(
    callable: &SemanticCallable,
    callable_node: Node<'a>,
    index: usize,
    state: &SemanticState<'a>,
) -> Vec<BindingIndex> {
    let Some(body_scope_id) = callable.body_scope_id.as_deref() else {
        return Vec::new();
    };
    let Some(&scope_index) = state.scopes_by_id.get(body_scope_id) else {
        return Vec::new();
    };
    let parameters = runtime_function_parameters(state.source, &callable_node);
    let mut bindings = state
        .scope(scope_index)
        .bindings
        .values()
        .filter_map(|binding_index| {
            let binding = state.binding(*binding_index);
            (binding.kind == DefinitionKind::Parameter
                && binding.definitions.iter().any(|definition| {
                    definition.kind == DefinitionKind::Parameter
                        && parameter_accepts_argument(
                            state,
                            &parameters,
                            definition.location,
                            index,
                        )
                }))
            .then_some(*binding_index)
        })
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| {
        state
            .binding(*left)
            .binding_id
            .cmp(&state.binding(*right).binding_id)
    });
    bindings
}

fn parameter_accepts_argument(
    state: &SemanticState<'_>,
    parameters: &[Node<'_>],
    definition_location: crate::javascript::parser::SourceRange,
    argument_index: usize,
) -> bool {
    let Some(parameter_index) = parameters
        .iter()
        .position(|parameter| range_contains(state.context.range(parameter), definition_location))
    else {
        return false;
    };

    parameter_index == argument_index
        || (parameter_index < argument_index
            && parameters[parameter_index].babel_type() == "RestElement")
}

fn range_contains(
    outer: crate::javascript::parser::SourceRange,
    inner: crate::javascript::parser::SourceRange,
) -> bool {
    outer.start.offset <= inner.start.offset && inner.end.offset <= outer.end.offset
}

fn unique_callable_ids(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use oxc_allocator::Allocator;

    use super::*;
    use crate::javascript::ast::{AstContext, AstVisitor, traverse};
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::state::ResolutionMode;

    struct Calls<'a> {
        calls: Vec<Node<'a>>,
    }

    impl<'a> AstVisitor<'a> for Calls<'a> {
        fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            if node.babel_type() == "CallExpression" {
                self.calls.push(*node);
            }
        }
    }

    fn call_callee<'a>(state: &SemanticState<'a>, source: &'a str, text: &str) -> Node<'a> {
        let mut calls = Calls { calls: Vec::new() };
        assert!(matches!(
            traverse(state.program, source, &mut calls, || {
                ControlFlow::<()>::Continue(())
            }),
            ControlFlow::Continue(())
        ));
        calls
            .calls
            .into_iter()
            .map(|call| call.field(source, Field::Callee).expect("callee"))
            .find(|callee| state.context.slice(callee.span()) == text)
            .unwrap_or_else(|| panic!("missing call to {text}"))
    }

    #[test]
    fn resolves_direct_alias_and_retains_incoming_value_uncertainty() {
        let source =
            "function fallback(){} function run(cb){ const local = fallback; local(); cb(); }";
        let allocator = Allocator::default();
        let parsed =
            parse_javascript_analysis_program(&allocator, source, Some("x.js")).expect("parse");
        let ControlFlow::Continue(state) = collect_definitions::<()>(
            AstContext::new(parsed.program),
            ResolutionMode::Import,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definitions cancelled");
        };
        let callable_nodes = callable_nodes(&state);
        let mut cache = HashMap::new();
        let fallback_id = callable_id_for_node(
            &state.context,
            &callable_nodes
                .values()
                .copied()
                .find(|node| state.context.slice(node.span()) == "function fallback(){}")
                .expect("fallback"),
        )
        .expect("fallback id");
        let local = resolve_local_callables(
            call_callee(&state, source, "local"),
            &state,
            &callable_nodes,
            &HashSet::new(),
            &mut cache,
        );
        assert_eq!(local.callable_ids, vec![fallback_id]);
        assert!(local.complete);

        let incoming = resolve_local_callables(
            call_callee(&state, source, "cb"),
            &state,
            &callable_nodes,
            &HashSet::new(),
            &mut cache,
        );
        assert!(!incoming.complete);
        assert!(incoming.callable_ids.is_empty());
    }

    #[test]
    fn resolves_both_conditional_candidates_with_complete_branches() {
        let source =
            "function left(){} function right(){} function run(flag){ (flag ? left : right)(); }";
        let allocator = Allocator::default();
        let parsed =
            parse_javascript_analysis_program(&allocator, source, Some("x.js")).expect("parse");
        let ControlFlow::Continue(state) = collect_definitions::<()>(
            AstContext::new(parsed.program),
            ResolutionMode::Import,
            || ControlFlow::Continue(()),
        ) else {
            panic!("definitions cancelled");
        };
        let callable_nodes = callable_nodes(&state);
        let mut calls = Calls { calls: Vec::new() };
        assert!(matches!(
            traverse(state.program, source, &mut calls, || {
                ControlFlow::<()>::Continue(())
            }),
            ControlFlow::Continue(())
        ));
        let callee = calls.calls[0].field(source, Field::Callee).expect("callee");
        let mut cache = HashMap::new();
        let result =
            resolve_local_callables(callee, &state, &callable_nodes, &HashSet::new(), &mut cache);
        assert_eq!(result.callable_ids.len(), 2);
        assert!(result.complete);
    }
}
