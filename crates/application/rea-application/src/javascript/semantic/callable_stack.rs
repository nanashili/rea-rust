//! Callable ownership during an enter/exit traversal.
//!
//! Computed object and class method keys run in the enclosing callable. The
//! method is therefore suspended while its key is visited, then restored for
//! its parameters and body. Every collector uses the same ownership rule.

use crate::javascript::ast::{AstContext, Field, Node, NodeMap};

use super::projection::callable_id_for_node;

#[derive(Clone, Debug)]
struct CallableFrame<C> {
    callable_id: String,
    callable: C,
}

/// Innermost-last stack of callables admitted by a collector.
///
/// Frames own their values; suspending a method moves its frame rather than
/// maintaining a second mutable list of callable values.
pub struct SemanticCallableStack<C> {
    frames: Vec<CallableFrame<C>>,
    suspended_methods: NodeMap<CallableFrame<C>>,
}

impl<C> Default for SemanticCallableStack<C> {
    fn default() -> Self {
        Self {
            frames: Vec::new(),
            suspended_methods: NodeMap::new(),
        }
    }
}

impl<C> SemanticCallableStack<C> {
    /// The innermost admitted callable, if the current node has an owner.
    pub fn current(&self) -> Option<&C> {
        self.frames.last().map(|frame| &frame.callable)
    }

    /// Admitted callable values from outermost to innermost.
    pub fn callables(&self) -> impl DoubleEndedIterator<Item = &C> {
        self.frames.iter().map(|frame| &frame.callable)
    }

    /// Enter a node, admitting its callable identity when the collector accepts it.
    pub fn enter<'a>(
        &mut self,
        context: &AstContext<'a>,
        node: &Node<'a>,
        parent: Option<&Node<'a>>,
        mut admit: impl FnMut(&str) -> Option<C>,
    ) {
        if let Some(parent) = parent
            && self.is_active_method_key(context, node, parent)
            && let Some(method) = self.frames.pop()
        {
            self.suspended_methods.insert(node.key(), method);
        }

        if let Some(callable_id) = callable_id_for_node(context, node)
            && let Some(callable) = admit(&callable_id)
        {
            self.frames.push(CallableFrame {
                callable_id,
                callable,
            });
        }
    }

    /// Exit a node and restore a method suspended by its computed key.
    pub fn exit(&mut self, context: &AstContext<'_>, node: &Node<'_>) {
        if let Some(callable_id) = callable_id_for_node(context, node)
            && self.frames.last().map(|frame| &frame.callable_id) == Some(&callable_id)
        {
            self.frames.pop();
        }

        if let Some(method) = self.suspended_methods.remove(&node.key()) {
            self.frames.push(method);
        }
    }

    fn is_active_method_key<'a>(
        &self,
        context: &AstContext<'a>,
        node: &Node<'a>,
        parent: &Node<'a>,
    ) -> bool {
        matches!(parent.babel_type(), "ObjectMethod" | "ClassMethod")
            && parent.computed()
            && parent
                .field(context.source(), Field::Key)
                .map(|key| key.key())
                == Some(node.key())
            && self.frames.last().map(|frame| &frame.callable_id)
                == callable_id_for_node(context, parent).as_ref()
    }
}
