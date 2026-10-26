//! Bounded child-argument shape proofs, without recovering named contents.

use std::cell::RefCell;
use std::collections::HashSet;
use std::ops::ControlFlow;

use crate::javascript::ast::{AstVisitor, Field, Node, NodeKey, traverse};
use crate::javascript::parser::RuntimeContext;

use super::ast_values::{
    is_erased_declaration, is_function, is_nullish_syntax, is_unmodeled_runtime_scope,
    unwrap_expression, unwrapped,
};
use super::limits::SEMANTIC_EXPRESSION_DEPTH_LIMIT;
use super::mutation_initializers::BindingReadStatus;
use super::opaque_effects::{
    OpaqueEffects, opaque_binding_read_may_have_changed, opaque_name_may_have_changed,
};
use super::state::{DeclarationKind, ScopeKind, SemanticState};
use super::value_types::ResourceLimit;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Array,
    Callback,
    Unknown,
}

#[derive(Default)]
struct NamedProofBlockers {
    blocked: bool,
    block_function_names: HashSet<String>,
}

/// The parser's runtime-context proof is supplied explicitly. Script syntax
/// alone does not establish whether top-level names are isolated.
pub struct ExpressionShapeResolver<'s, 'a> {
    state: &'s SemanticState<'a>,
    opaque_effects: &'s OpaqueEffects<'a>,
    runtime_context: RuntimeContext,
    named_blockers: RefCell<Option<NamedProofBlockers>>,
}

impl<'s, 'a> ExpressionShapeResolver<'s, 'a> {
    pub fn new(
        state: &'s SemanticState<'a>,
        opaque_effects: &'s OpaqueEffects<'a>,
        runtime_context: RuntimeContext,
    ) -> Self {
        Self {
            state,
            opaque_effects,
            runtime_context,
            named_blockers: RefCell::new(None),
        }
    }

    pub fn is_array(&self, node: Node<'a>) -> bool {
        self.shape(node) == Shape::Array
    }

    pub fn is_callback(&self, node: Node<'a>) -> bool {
        self.shape(node) == Shape::Callback
    }

    pub fn is_nullish(&self, input: Node<'a>) -> bool {
        let node = unwrapped(self.state.source, input);
        is_nullish_syntax(self.state.source, node)
            || (self.state.is_unshadowed_global(&node, "undefined")
                && !self.named_proof_blocked(None)
                && !opaque_name_may_have_changed(self.opaque_effects, self.state, node, None))
    }

    fn shape(&self, input: Node<'a>) -> Shape {
        let mut node = input;
        let mut depth = 0;
        let mut seen = HashSet::<NodeKey>::new();

        loop {
            let unwrapped = unwrap_expression(self.state.source, node, false);
            node = unwrapped.node;
            depth += unwrapped.depth;
            if depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT {
                self.state
                    .record_value_resource_limit(ResourceLimit::ExpressionDepth);
                return Shape::Unknown;
            }
            if !seen.insert(node.key()) {
                return Shape::Unknown;
            }
            if node.babel_type() == "ArrayExpression" {
                return Shape::Array;
            }
            if is_function(&node) && !is_erased_declaration(node) {
                return Shape::Callback;
            }

            let Some(initializer) = self.named_initializer(node) else {
                return Shape::Unknown;
            };
            node = initializer;
            depth += 1;
        }
    }

    fn named_initializer(&self, node: Node<'a>) -> Option<Node<'a>> {
        let name = node.identifier_name()?;
        let index = self.state.resolve_binding(&node, name)?;
        let binding = self.state.binding(index);
        if !binding.reference_initializers.is_empty() {
            return None;
        }
        let program_binding = self
            .state
            .scopes_by_id
            .get(&binding.scope_id)
            .is_some_and(|index| self.state.scope(*index).kind == ScopeKind::Program);
        if program_binding
            && (self.runtime_context == RuntimeContext::Unknown
                || (self.runtime_context == RuntimeContext::Commonjs
                    && commonjs_wrapper_parameter(name)))
        {
            return None;
        }

        let annex_b_name = binding
            .declaration_kinds
            .contains(&DeclarationKind::Var)
            .then_some(name);
        if self.named_proof_blocked(annex_b_name)
            || opaque_binding_read_may_have_changed(self.opaque_effects, self.state, binding, node)
        {
            return None;
        }
        let initializer = self.state.stable_initializer(index)?;
        if !initializer.projection.is_empty() {
            return None;
        }
        let read = self.state.semantic_binding_at_read(binding, node);
        if !hoisted_function(self.state, initializer.node)
            && (read.status != BindingReadStatus::Ordered || !read.has_definite_initializer)
        {
            return None;
        }
        Some(initializer.node)
    }

    fn named_proof_blocked(&self, annex_b_name: Option<&str>) -> bool {
        let mut cached = self.named_blockers.borrow_mut();
        let blockers = cached
            .get_or_insert_with(|| collect_named_proof_blockers(self.state, self.runtime_context));
        blockers.blocked
            || annex_b_name.is_some_and(|name| blockers.block_function_names.contains(name))
    }
}

fn commonjs_wrapper_parameter(name: &str) -> bool {
    matches!(
        name,
        "exports" | "require" | "module" | "__filename" | "__dirname"
    )
}

fn hoisted_function<'a>(state: &SemanticState<'a>, node: Node<'a>) -> bool {
    if node.babel_type() != "FunctionDeclaration" {
        return false;
    }
    let Some(parent) = state.parents.get(&node.key()) else {
        return false;
    };
    parent.babel_type() == "Program"
        || (parent.babel_type() == "BlockStatement"
            && state.parents.get(&parent.key()).is_some_and(is_function))
}

fn collect_named_proof_blockers<'a>(
    state: &SemanticState<'a>,
    runtime_context: RuntimeContext,
) -> NamedProofBlockers {
    struct Collector<'s, 'a> {
        state: &'s SemanticState<'a>,
        runtime_context: RuntimeContext,
        blockers: NamedProofBlockers,
    }

    impl<'a> AstVisitor<'a> for Collector<'_, 'a> {
        fn enter(&mut self, node: &Node<'a>, _parent: Option<&Node<'a>>, _ancestors: &[Node<'a>]) {
            self.blockers.blocked |=
                is_erased_declaration(*node) || is_unmodeled_runtime_scope(*node);
            if self.runtime_context != RuntimeContext::Module
                && node.babel_type() == "FunctionDeclaration"
                && !hoisted_function(self.state, *node)
                && let Some(name) = node
                    .field(self.state.source, Field::Id)
                    .and_then(|id| id.identifier_name())
            {
                self.blockers.block_function_names.insert(name.to_owned());
            }
        }
    }

    let mut collector = Collector {
        state,
        runtime_context,
        blockers: NamedProofBlockers::default(),
    };
    let completed = traverse(state.program, state.source, &mut collector, || {
        ControlFlow::<()>::Continue(())
    });
    debug_assert!(matches!(completed, ControlFlow::Continue(())));
    collector.blockers
}
