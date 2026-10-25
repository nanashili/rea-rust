//! Direct and indirect `eval` indexing for the semantic scope owner.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::rc::Rc;

use crate::javascript::ast::{AstVisitor, Field, Node, traverse};

use super::ast_values::{is_class, is_function, unwrap_expression};
use super::module_interop::{ModuleInterop, create_module_interop_for_global_eval};
use super::mutation_initializers::{
    EffectTiming, effect_timing, semantic_binding_effect_follows_capture,
};
use super::state::{BindingState, SemanticState};

#[derive(Clone, Debug, Default)]
pub struct OpaqueEffects<'a> {
    pub sites: HashSet<crate::javascript::ast::NodeKey>,
    pub sloppy_sites: HashSet<crate::javascript::ast::NodeKey>,
    pub by_scope: HashMap<String, Vec<Node<'a>>>,
    /// Descendant scope ids in JavaScript `Set` insertion order.
    pub children: HashMap<String, Vec<String>>,
    pub global_sites: Rc<Vec<Node<'a>>>,
}

/// Index direct eval candidates and retain the scope tree needed by later
/// binding queries.  Scope ownership remains in `SemanticState`.
pub fn index_opaque_effects<'a>(state: &SemanticState<'a>) -> OpaqueEffects<'a> {
    let mut effects = OpaqueEffects::default();
    for (node, scope_id) in &state.opaque_candidates {
        let Some(callee) = node.field(state.source, Field::Callee) else {
            continue;
        };
        let callee = unwrap_expression(state.source, callee, false).node;
        if callee.identifier_name() != Some("eval") || !state.is_unshadowed_global(&callee, "eval")
        {
            continue;
        }
        effects.sites.insert(node.key());
        if !strict_eval(state, node) {
            effects.sloppy_sites.insert(node.key());
        }
        effects
            .by_scope
            .entry(scope_id.clone())
            .or_default()
            .push(*node);
        let mut child = scope_id.clone();
        while let Some(index) = state.scopes_by_id.get(&child).copied() {
            let Some(parent) = state.scope(index).parent_scope_id.clone() else {
                break;
            };
            let children = effects.children.entry(parent.clone()).or_default();
            if !children.iter().any(|candidate| candidate == &child) {
                children.push(child);
            }
            child = parent;
        }
    }
    index_global_sites(state, &mut effects);
    effects
}

/// Find eval invocations through the canonical intrinsic resolver.  The
/// resolver owns direct, alias, and `globalThis` identity facts, so this
/// observer does not maintain a second path or binding index.
///
/// `global_sites` intentionally includes direct eval as well as indirect eval;
/// that is the TypeScript owner’s complete opaque-effects fact.  The separate
/// `sites` and `sloppy_sites` sets retain the narrower binding-effect queries.
fn index_global_sites<'a, 's>(state: &'s SemanticState<'a>, effects: &mut OpaqueEffects<'a>) {
    if !state.may_reference_global_eval {
        return;
    }

    if let Some(cached) = state.global_eval_sites_cache.borrow().as_ref() {
        effects.global_sites = Rc::clone(cached);
        return;
    }

    let mut observer = GlobalEvalObserver {
        interop: create_module_interop_for_global_eval(state),
        sites: Vec::new(),
    };
    let _ = traverse(state.program, state.source, &mut observer, || {
        ControlFlow::<()>::Continue(())
    });
    let sites = Rc::new(observer.sites);
    *state.global_eval_sites_cache.borrow_mut() = Some(Rc::clone(&sites));
    effects.global_sites = sites;
}

struct GlobalEvalObserver<'s, 'a> {
    interop: ModuleInterop<'a, 's>,
    sites: Vec<Node<'a>>,
}

impl<'a, 's> AstVisitor<'a> for GlobalEvalObserver<'s, 'a> {
    fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
        if !matches!(
            node.babel_type(),
            "CallExpression" | "OptionalCallExpression"
        ) {
            return;
        }
        let Some(invocation) = self.interop.intrinsic_invocation(*node) else {
            return;
        };
        if invocation
            .path
            .iter()
            .map(String::as_str)
            .eq(["intrinsic", "global", "eval"])
        {
            self.sites.push(*node);
        }
    }
}

/// Return eval sites visible from a binding's activation.
pub fn binding_effects<'a>(
    effects: &OpaqueEffects<'a>,
    state: &SemanticState<'a>,
    binding: &BindingState<'a>,
    references: bool,
) -> Vec<Node<'a>> {
    let mut pending = vec![if references {
        activation_scope(&binding.scope_id, state)
    } else {
        binding.scope_id.clone()
    }];
    let mut result = Vec::new();
    while let Some(scope_id) = pending.pop() {
        for node in effects.by_scope.get(&scope_id).into_iter().flatten() {
            if references
                || state
                    .resolve_binding(node, &binding.name)
                    .is_some_and(|index| state.binding(index).binding_id == binding.binding_id)
            {
                result.push(*node);
            }
        }
        // The TypeScript implementation pushes children in insertion order
        // onto a LIFO worklist. Extending in insertion order preserves that
        // same reverse-insertion visit order when the next scope is popped.
        if let Some(children) = effects.children.get(&scope_id) {
            pending.extend(children.iter().cloned());
        }
    }
    result
}

/// Whether an eval can affect a binding before `read`.
pub fn binding_may_have_opaque_effect<'a>(
    effects: &OpaqueEffects<'a>,
    state: &SemanticState<'a>,
    binding: &BindingState<'a>,
    read: Option<Node<'a>>,
    references: bool,
) -> bool {
    binding_effects(effects, state, binding, references)
        .into_iter()
        .any(|effect| {
            read.is_none_or(|read| {
                effect_timing(read, Some(effect), state, state.source) != EffectTiming::After
                    && !semantic_binding_effect_follows_capture(
                        binding,
                        read,
                        effect,
                        &state.parents,
                        state.source,
                    )
            })
        })
}

/// Declaration assignability is independent of explicit write observations.
pub fn binding_can_be_rebound(binding: &BindingState<'_>) -> bool {
    binding.mutable
        || (binding.definitions.iter().any(|definition| {
            matches!(
                definition.kind,
                super::state::DefinitionKind::Function | super::state::DefinitionKind::Class
            )
        }) && binding.initializers.iter().any(|initializer| {
            matches!(
                initializer.node.babel_type(),
                "FunctionDeclaration" | "ClassDeclaration"
            )
        }))
}

/// Whether an indirect eval may have changed a global before `read`.
pub fn opaque_global_may_have_changed<'a>(
    read: Node<'a>,
    state: &SemanticState<'a>,
    effects: &OpaqueEffects<'a>,
) -> bool {
    effects.global_sites.iter().any(|effect| {
        effect_timing(read, Some(*effect), state, state.source) != EffectTiming::After
    })
}

/// Whether an eval may introduce or rebind a visible name before `read`.
pub fn opaque_name_may_have_changed<'a>(
    effects: &OpaqueEffects<'a>,
    state: &SemanticState<'a>,
    read: Node<'a>,
    binding: Option<&BindingState<'a>>,
) -> bool {
    let Some(mut scope_index) = state.scope_for_node(&read) else {
        return false;
    };
    let mut visible = HashSet::new();
    loop {
        visible.insert(state.scope(scope_index).scope_id.clone());
        let Some(parent) = state.parent_scope(scope_index) else {
            break;
        };
        scope_index = parent;
    }
    let binding_activation = binding.map(|binding| activation_scope(&binding.scope_id, state));
    for (scope_id, sites) in &effects.by_scope {
        let Some(mut activation) = state.scopes_by_id.get(scope_id).copied() else {
            continue;
        };
        while !matches!(
            state.scope(activation).kind,
            super::state::ScopeKind::Function | super::state::ScopeKind::Program
        ) {
            let Some(parent) = state.parent_scope(activation) else {
                break;
            };
            activation = parent;
        }
        let activation_id = state.scope(activation).scope_id.as_str();
        if !visible.contains(activation_id) || binding_activation.as_deref() == Some(activation_id)
        {
            continue;
        }
        if sites.iter().any(|effect| {
            effects.sloppy_sites.contains(&effect.key())
                && binding.is_none_or(|binding| {
                    state
                        .resolve_binding(effect, &binding.name)
                        .is_some_and(|index| state.binding(index).binding_id == binding.binding_id)
                })
                && effect_timing(read, Some(*effect), state, state.source) != EffectTiming::After
        }) {
            return true;
        }
    }
    false
}

/// Whether a binding read can have changed through eval or a newly introduced
/// name in a visible activation.
pub fn opaque_binding_read_may_have_changed<'a>(
    effects: &OpaqueEffects<'a>,
    state: &SemanticState<'a>,
    binding: &BindingState<'a>,
    read: Node<'a>,
) -> bool {
    (binding_can_be_rebound(binding)
        && binding_may_have_opaque_effect(effects, state, binding, Some(read), false))
        || opaque_name_may_have_changed(effects, state, read, Some(binding))
}

fn activation_scope(scope_id: &str, state: &SemanticState<'_>) -> String {
    let mut current = state.scopes_by_id.get(scope_id).copied();
    while let Some(index) = current {
        let scope = state.scope(index);
        if matches!(
            scope.kind,
            super::state::ScopeKind::Function | super::state::ScopeKind::Program
        ) {
            return scope.scope_id.clone();
        }
        current = state.parent_scope(index);
    }
    scope_id.to_owned()
}

fn strict_eval<'a>(state: &SemanticState<'a>, site: &Node<'a>) -> bool {
    let mut current = Some(*site);
    while let Some(node) = current {
        if is_class(&node) {
            return true;
        }
        if node.babel_type() == "Program" && !state.script {
            return true;
        }
        if node.has_use_strict_directive() {
            return true;
        }
        if is_function(&node) {
            if let Some(body) = node.field(state.source, Field::Body) {
                if body.has_use_strict_directive() {
                    return true;
                }
            }
        }
        current = state.parent_of(&node);
    }
    false
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use oxc_allocator::Allocator;

    use super::index_opaque_effects;
    use crate::javascript::ast::AstContext;
    use crate::javascript::parser::parse_javascript_analysis_program;
    use crate::javascript::semantic::definitions::collect_definitions;
    use crate::javascript::semantic::state::ResolutionMode;

    #[test]
    fn marks_function_declarations_with_strict_directives_as_strict_eval() {
        let source = concat!(
            "eval('program');",
            "function strictDeclaration() { 'use strict'; eval('strict'); }",
            "function sloppyDeclaration() { eval('sloppy'); }",
        );
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

        let effects = index_opaque_effects(&state);
        let outcomes = state
            .opaque_candidates
            .iter()
            .map(|(node, _)| {
                (
                    state.context.slice(node.span()),
                    effects.sloppy_sites.contains(&node.key()),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            outcomes,
            vec![
                ("eval('program')", true),
                ("eval('strict')", false),
                ("eval('sloppy')", true),
            ]
        );
    }

    #[test]
    fn observes_indirect_global_eval_through_intrinsic_aliases() {
        let source = concat!(
            "global.eval('global');",
            "globalThis.eval('globalThis');",
            "const call = global.eval; call('alias');",
            "eval('direct');",
        );
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

        let effects = index_opaque_effects(&state);
        let sites = effects
            .global_sites
            .iter()
            .map(|node| state.context.slice(node.span()))
            .collect::<Vec<_>>();
        assert_eq!(
            sites,
            vec![
                "global.eval('global')",
                "globalThis.eval('globalThis')",
                "call('alias')",
                "eval('direct')",
            ]
        );
    }

    #[test]
    fn cached_global_eval_sites_keep_shadowed_eval_unknown() {
        let source = concat!(
            "function shadow(eval) { eval('local'); }",
            "globalThis.eval('global');",
        );
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

        let first = index_opaque_effects(&state);
        let second = index_opaque_effects(&state);
        let sites = |effects: &super::OpaqueEffects<'_>| {
            effects
                .global_sites
                .iter()
                .map(|node| state.context.slice(node.span()))
                .collect::<Vec<_>>()
        };

        assert_eq!(sites(&first), vec!["globalThis.eval('global')"]);
        assert_eq!(sites(&second), sites(&first));
    }

    #[test]
    fn global_eval_alias_reassignment_is_not_retained_by_the_cache() {
        let source = concat!(
            "let call = global.eval; call('before');",
            "call = console.log; call('after');",
        );
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

        let effects = index_opaque_effects(&state);
        let sites = effects
            .global_sites
            .iter()
            .map(|node| state.context.slice(node.span()))
            .collect::<Vec<_>>();
        assert_eq!(sites, vec!["call('before')"]);
    }
}
