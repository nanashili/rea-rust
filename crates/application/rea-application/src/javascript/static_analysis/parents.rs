//! Parent links of the Babel view, in the shape of TS `parentsByNode`.

use std::ops::ControlFlow;

use crate::javascript::ast::{AstContext, AstVisitor, Node, NodeMap, traverse};

/// Every node's Babel parent, built by one traversal from the program root.
pub struct ParentMap<'a> {
    parents: NodeMap<Node<'a>>,
}

impl<'a> ParentMap<'a> {
    pub fn new(context: &AstContext<'a>) -> Self {
        struct Collect<'a> {
            parents: NodeMap<Node<'a>>,
        }
        impl<'a> AstVisitor<'a> for Collect<'a> {
            fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _: &[Node<'a>]) {
                if let Some(parent) = parent {
                    self.parents.insert(node.key(), *parent);
                }
            }
        }
        let mut collect = Collect {
            parents: NodeMap::default(),
        };
        let _: ControlFlow<()> = traverse(context.root(), context.source(), &mut collect, || {
            ControlFlow::Continue(())
        });
        Self {
            parents: collect.parents,
        }
    }

    pub fn parent(&self, node: &Node<'a>) -> Option<Node<'a>> {
        self.parents.get(&node.key()).copied()
    }
}
