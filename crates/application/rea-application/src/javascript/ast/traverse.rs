//! Port of `javascriptSemanticTraversal.traverseJavaScriptAstSteps`.

use std::ops::ControlFlow;

use super::node::Node;

/// Callbacks for one deterministic traversal (`JavaScriptAstVisitor`).
pub trait AstVisitor<'a> {
    /// Omit a child and its subtree without entering or exiting it.
    fn skip(&mut self, _node: &Node<'a>) -> bool {
        false
    }

    /// `ancestors` is outermost-first and ends with the direct parent.
    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, ancestors: &[Node<'a>]);

    fn exit(&mut self, _node: &Node<'a>, _parent: Option<&Node<'a>>) {}
}

/// Visited nodes between cancellation checkpoints (the TS generator yields
/// at the same points).
pub const TRAVERSAL_CHECKPOINT_INTERVAL: usize = 1024;

struct Frame<'a> {
    node: Node<'a>,
    children: Vec<Node<'a>>,
    next: usize,
}

/// Visit `root` and its descendants in Babel `VISITOR_KEYS` order.
/// `checkpoint` runs every [`TRAVERSAL_CHECKPOINT_INTERVAL`] visited nodes;
/// returning `Break` stops the traversal (cancellation) and is returned.
pub fn traverse<'a, B>(
    root: Node<'a>,
    source: &'a str,
    visitor: &mut impl AstVisitor<'a>,
    mut checkpoint: impl FnMut() -> ControlFlow<B>,
) -> ControlFlow<B> {
    let mut ancestors: Vec<Node<'a>> = Vec::new();
    visitor.enter(&root, None, &ancestors);
    ancestors.push(root);
    let mut pending = vec![Frame {
        node: root,
        children: root.children(source),
        next: 0,
    }];
    let mut visited = 1usize;
    while let Some(current) = pending.last_mut() {
        if let Some(&child) = current.children.get(current.next) {
            current.next += 1;
            if visited.is_multiple_of(TRAVERSAL_CHECKPOINT_INTERVAL) {
                checkpoint()?;
            }
            visited += 1;
            if visitor.skip(&child) {
                continue;
            }
            visitor.enter(&child, ancestors.last(), &ancestors);
            ancestors.push(child);
            pending.push(Frame {
                node: child,
                children: child.children(source),
                next: 0,
            });
        } else {
            let node = current.node;
            ancestors.pop();
            pending.pop();
            visitor.exit(&node, ancestors.last());
        }
    }
    ControlFlow::Continue(())
}
