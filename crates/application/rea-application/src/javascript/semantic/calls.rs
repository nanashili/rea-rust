//! Call-site, flow, capture, and unsupported-frontier collection.
//!
//! This is the Rust counterpart of `javascriptSemanticCalls.ts`.  The pass
//! only records syntax and already-owned state facts; it does not infer a
//! callable target when local resolution is incomplete.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use crate::javascript::ast::{AstVisitor, Field, Node, traverse};
use crate::javascript::contracts::semantic_ir::{
    SemanticArgumentFlow, SemanticCallArgument, SemanticCallResultFlow, SemanticCallReturnFlow,
    SemanticCallSite, SemanticCallable as ContractCallable, SemanticClosureCapture,
    SemanticFrontier,
};

use super::ast_values::{is_member, static_property_key};
use super::call_resolution::{
    LocalCallableResolution, callable_nodes, parameter_bindings, resolve_local_callables,
};
use super::callable_stack::SemanticCallableStack;
use super::data_effect_helpers::assigned_semantic_result_bindings;
use super::opaque_effects::index_opaque_effects;
use super::projection::SemanticCallable;
use super::reference_role::semantic_reference_role;
use super::state::{BindingIndex, SemanticState};

fn contract_range(
    range: crate::javascript::parser::SourceRange,
) -> crate::javascript::contracts::static_analysis::SourceRange {
    crate::javascript::contracts::static_analysis::SourceRange {
        start: crate::javascript::contracts::static_analysis::SourcePoint {
            line: range.start.line,
            column: range.start.column,
        },
        end: crate::javascript::contracts::static_analysis::SourcePoint {
            line: range.end.line,
            column: range.end.column,
        },
    }
}

#[derive(Clone, Debug, Default)]
pub struct SemanticCallAnalysis {
    pub call_sites: Vec<SemanticCallSite>,
    pub argument_flows: Vec<SemanticArgumentFlow>,
    pub call_return_flows: Vec<SemanticCallReturnFlow>,
    pub call_result_flows: Vec<SemanticCallResultFlow>,
    pub closure_captures: Vec<SemanticClosureCapture>,
    pub frontiers: Vec<SemanticFrontier>,
}

struct Collector<'s, 'a, 'c> {
    state: &'s SemanticState<'a>,
    contract_callables: &'c HashMap<String, &'c ContractCallable>,
    callable_nodes: HashMap<String, Node<'a>>,
    callable_stack: SemanticCallableStack<String>,
    callables: HashMap<String, SemanticCallable>,
    binding_cache: HashMap<crate::javascript::ast::NodeKey, LocalCallableResolution>,
    parameter_cache: HashMap<(String, usize), Vec<BindingIndex>>,
    output: SemanticCallAnalysis,
    ancestors: Vec<Node<'a>>,
    opaque_sites: HashSet<crate::javascript::ast::NodeKey>,
}

/// Collect all call facts for the admitted callable projection.
pub fn collect_semantic_calls<'s, 'a>(
    state: &'s SemanticState<'a>,
    callables: &'s [ContractCallable],
) -> SemanticCallAnalysis {
    let callable_nodes = callable_nodes(state);
    let internal = callables
        .iter()
        .map(|callable| SemanticCallable {
            callable_id: callable.callable_id.clone(),
            kind: callable.kind.clone(),
            name: callable.name.clone(),
            container_scope_id: callable.container_scope_id.clone(),
            body_scope_id: callable.body_scope_id.clone(),
            location: callable_nodes
                .get(&callable.callable_id)
                .map(|node| state.context.range(node))
                .unwrap_or_else(|| state.context.range(&state.program)),
        })
        .collect::<Vec<_>>();
    let contract_map = callables
        .iter()
        .map(|callable| (callable.callable_id.clone(), callable))
        .collect::<HashMap<_, _>>();
    let contract_callables = &contract_map;
    let mut collector = Collector {
        state,
        contract_callables,
        callable_nodes,
        callable_stack: SemanticCallableStack::default(),
        callables: internal
            .into_iter()
            .map(|c| (c.callable_id.clone(), c))
            .collect(),
        binding_cache: HashMap::new(),
        parameter_cache: HashMap::new(),
        output: SemanticCallAnalysis::default(),
        ancestors: Vec::new(),
        opaque_sites: index_opaque_effects(state).sites,
    };
    let callable_ids = collector.callables.keys().cloned().collect::<HashSet<_>>();
    let _ = traverse(
        state.program,
        state.source,
        &mut CallsVisitor {
            collector: &mut collector,
            callable_ids,
        },
        || ControlFlow::<()>::Continue(()),
    );
    collector.output
}

struct CallsVisitor<'c, 's, 'a, 'm> {
    collector: &'c mut Collector<'s, 'a, 'm>,
    callable_ids: HashSet<String>,
}

impl<'a> AstVisitor<'a> for CallsVisitor<'_, '_, 'a, '_> {
    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]) {
        let c = &mut self.collector;
        c.callable_stack
            .enter(&c.state.context, node, parent, |id| {
                self.callable_ids.contains(id).then(|| id.to_owned())
            });
        let owner = c.enclosing_function_owner();
        if node.babel_type() == "Identifier" && parent.is_some() {
            c.collect_capture(*node, *parent.expect("checked"), owner.as_deref());
        }
        c.collect_dynamic_property(*node, owner.as_deref());
        c.collect_dynamic_scope(*node, owner.as_deref());
        if matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression" | "NewExpression"
        ) {
            c.collect_call(*node, owner.as_deref(), ancestors);
        }
        c.ancestors.push(*node);
    }

    fn exit(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>) {
        self.collector.ancestors.pop();
        self.collector
            .callable_stack
            .exit(&self.collector.state.context, node);
        let _ = parent;
    }
}

impl<'s, 'a, 'c> Collector<'s, 'a, 'c> {
    fn enclosing_function_owner(&self) -> Option<String> {
        self.callable_stack
            .callables()
            .rev()
            .find(|callable_id| {
                self.callables
                    .get(*callable_id)
                    .is_some_and(|callable| callable.kind != "class")
            })
            .cloned()
    }

    fn owner_id(owner: Option<&str>) -> Option<String> {
        owner.map(str::to_owned)
    }

    fn collect_call(&mut self, node: Node<'a>, owner: Option<&str>, ancestors: &[Node<'a>]) {
        let Some(callee) = node.field(self.state.source, Field::Callee) else {
            return;
        };
        let resolution = resolve_local_callables(
            callee,
            self.state,
            &self.callable_nodes,
            &HashSet::new(),
            &mut self.binding_cache,
        );
        let call_site_id = format!(
            "call:{}:{}:{}",
            if node.babel_type() == "NewExpression" {
                "construct"
            } else {
                "call"
            },
            self.state.context.start(&node),
            self.state.context.end(&node)
        );
        let arguments = node
            .field_list(self.state.source, Field::Arguments)
            .into_iter()
            .enumerate()
            .filter_map(|(index, argument)| {
                argument.map(|argument| SemanticCallArgument {
                    index,
                    location: contract_range(self.state.context.range(&argument)),
                    spread: argument.babel_type() == "SpreadElement",
                })
            })
            .collect::<Vec<_>>();
        let resolution_kind = if resolution.callable_ids.len() == 1 && resolution.complete {
            "exact"
        } else if !resolution.callable_ids.is_empty() {
            "ambiguous"
        } else {
            "unresolved"
        };
        let site = SemanticCallSite {
            call_site_id,
            kind: if node.babel_type() == "NewExpression" {
                "construct"
            } else {
                "call"
            }
            .to_owned(),
            caller_callable_id: Self::owner_id(owner),
            location: contract_range(self.state.context.range(&node)),
            callee_location: contract_range(self.state.context.range(&callee)),
            resolution: resolution_kind.to_owned(),
            callee_callable_ids: resolution.callable_ids.clone(),
            arguments,
        };
        if site.resolution != "exact" {
            self.output.frontiers.push(SemanticFrontier {
                kind: "dynamic-call".to_owned(),
                callable_id: Self::owner_id(owner),
                location: contract_range(self.state.context.range(&callee)),
                reason: resolution.reason,
            });
        }
        self.collect_call_result(&site, node, ancestors);
        self.collect_argument_flows(&site, node);
        if site.kind == "call" {
            self.collect_return_flows(&site);
        }
        self.output.call_sites.push(site);
    }

    fn collect_call_result(
        &mut self,
        site: &SemanticCallSite,
        node: Node<'a>,
        ancestors: &[Node<'a>],
    ) {
        for assigned in assigned_semantic_result_bindings(node, ancestors, self.state)
            .into_iter()
            .filter(|entry| entry.projection_path.is_empty())
        {
            let Some(index) = self.state.bindings_by_id.get(&assigned.binding_id).copied() else {
                continue;
            };
            let binding = self.state.binding(index);
            let identifier_range = contract_range(self.state.context.range(&assigned.identifier));
            let Some(definition) = binding
                .definitions
                .iter()
                .find(|definition| contract_range(definition.location) == identifier_range)
            else {
                continue;
            };
            self.output.call_result_flows.push(SemanticCallResultFlow {
                call_site_id: site.call_site_id.clone(),
                binding_id: binding.binding_id.clone(),
                definition_location: contract_range(definition.location),
            });
        }
    }

    fn collect_argument_flows(&mut self, site: &SemanticCallSite, node: Node<'a>) {
        let retained = site
            .arguments
            .iter()
            .map(|argument| argument.index)
            .collect::<HashSet<_>>();
        let mut exact = true;
        for (index, argument) in node
            .field_list(self.state.source, Field::Arguments)
            .into_iter()
            .enumerate()
        {
            let Some(argument) = argument else { continue };
            if argument.babel_type() == "SpreadElement" {
                exact = false;
                continue;
            }
            if !exact || !retained.contains(&index) {
                continue;
            }
            for callable_id in &site.callee_callable_ids {
                let Some(callable) = self.callables.get(callable_id) else {
                    continue;
                };
                let key = (callable_id.clone(), index);
                let bindings = if let Some(cached) = self.parameter_cache.get(&key) {
                    cached.clone()
                } else {
                    let Some(callable_node) = self.callable_nodes.get(callable_id) else {
                        continue;
                    };
                    let values = parameter_bindings(callable, *callable_node, index, self.state);
                    self.parameter_cache.insert(key, values.clone());
                    values
                };
                for parameter_index in bindings {
                    let parameter = self.state.binding(parameter_index);
                    let Some(definition) = parameter
                        .definitions
                        .iter()
                        .find(|d| matches!(d.kind, super::state::DefinitionKind::Parameter))
                    else {
                        continue;
                    };
                    self.output.argument_flows.push(SemanticArgumentFlow {
                        call_site_id: site.call_site_id.clone(),
                        argument_index: index,
                        argument_location: contract_range(self.state.context.range(&argument)),
                        callable_id: callable_id.clone(),
                        parameter_binding_id: parameter.binding_id.clone(),
                        parameter_location: contract_range(definition.location),
                    });
                }
            }
        }
    }

    fn collect_return_flows(&mut self, site: &SemanticCallSite) {
        for callable_id in &site.callee_callable_ids {
            let Some(callable) = self.contract_callables.get(callable_id) else {
                continue;
            };
            for return_site in &callable.return_sites {
                self.output.call_return_flows.push(SemanticCallReturnFlow {
                    call_site_id: site.call_site_id.clone(),
                    callable_id: callable_id.clone(),
                    return_site_id: return_site.return_site_id.clone(),
                    return_location: return_site.location,
                });
            }
        }
    }

    fn collect_capture(&mut self, node: Node<'a>, parent: Node<'a>, owner: Option<&str>) {
        let Some(owner) = owner else { return };
        let Some(_role) =
            semantic_reference_role(self.state.source, &node, &parent, &self.ancestors)
        else {
            return;
        };
        let Some(name) = node.identifier_name() else {
            return;
        };
        let Some(binding_index) = self.state.resolve_binding(&node, name) else {
            return;
        };
        let binding = self.state.binding(binding_index);
        let Some(callable) = self.callables.get(owner) else {
            return;
        };
        let Some(owner_scope) = callable.body_scope_id.as_deref() else {
            return;
        };
        let within = self.binding_within(binding.scope_id.as_str(), owner_scope);
        if !within {
            self.output.closure_captures.push(SemanticClosureCapture {
                callable_id: owner.to_owned(),
                binding_id: binding.binding_id.clone(),
                reference_location: contract_range(self.state.context.range(&node)),
            });
        }
    }

    fn binding_within(&self, binding_scope: &str, owner_scope: &str) -> bool {
        let mut current = Some(binding_scope.to_owned());
        while let Some(scope_id) = current {
            if scope_id == owner_scope {
                return true;
            }
            current = self
                .state
                .scopes_by_id
                .get(&scope_id)
                .and_then(|index| self.state.scope(*index).parent_scope_id.clone());
        }
        false
    }

    fn collect_dynamic_property(&mut self, node: Node<'a>, owner: Option<&str>) {
        let dynamic = if is_member(&node) {
            node.field(self.state.source, Field::Property)
                .is_some_and(|property| {
                    static_property_key(self.state.source, property, node.computed()).is_none()
                })
        } else if matches!(node.babel_type(), "ObjectProperty" | "ObjectMethod") && node.computed()
        {
            node.field(self.state.source, Field::Key)
                .is_some_and(|key| static_property_key(self.state.source, key, true).is_none())
        } else {
            false
        };
        if dynamic {
            let reason = if is_member(&node) {
                "Computed member property is not a static string or number."
            } else {
                "Computed object property is not a static string or number."
            };
            let property = node
                .field(
                    self.state.source,
                    if is_member(&node) {
                        Field::Property
                    } else {
                        Field::Key
                    },
                )
                .unwrap_or(node);
            self.output.frontiers.push(SemanticFrontier {
                kind: "dynamic-property".to_owned(),
                callable_id: Self::owner_id(owner),
                location: contract_range(self.state.context.range(&property)),
                reason: reason.to_owned(),
            });
        }
    }

    fn collect_dynamic_scope(&mut self, node: Node<'a>, owner: Option<&str>) {
        let reason = if node.babel_type() == "WithStatement" {
            Some("`with` introduces a runtime binding environment; names inside are not statically resolvable.".to_owned())
        } else if self.opaque_sites.contains(&node.key()) {
            Some("`eval` can change bindings and reachable objects at runtime; its effects are not statically resolvable.".to_owned())
        } else {
            None
        };
        if let Some(reason) = reason {
            self.output.frontiers.push(SemanticFrontier {
                kind: "dynamic-scope".to_owned(),
                callable_id: Self::owner_id(owner),
                location: contract_range(self.state.context.range(&node)),
                reason,
            });
        }
    }
}
