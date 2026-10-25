//! Compact parent links for one traversal of the Babel view.

use std::collections::HashMap;
use std::num::NonZeroU32;

use super::{Node, NodeKey, Role};

#[derive(Clone, Copy, Default)]
struct NodeSlot {
    parent: Option<NonZeroU32>,
    retained: Option<NonZeroU32>,
}

/// Parents retain the exact Babel views produced by the traversal, including
/// synthesized roles, folded methods, spans and parentheses. Each parent view
/// is stored once; children hold compact indexes instead of repeating it.
///
/// Oxc assigns dense node IDs within one parsed source. Primary links use that
/// existing identity directly. Synthesized views are sparse and have a separate
/// table so they neither collide with primary views nor double the dense array.
#[derive(Default)]
pub struct NodeParents<'a> {
    primary: Vec<NodeSlot>,
    synthesized: HashMap<u32, NodeSlot>,
    retained: Vec<Node<'a>>,
    links: usize,
}

impl<'a> NodeParents<'a> {
    pub fn insert(&mut self, child: NodeKey, parent: Node<'a>) {
        let parent_index = self.retain(parent);
        let child_slot = self.slot_mut(child);
        let replacing = child_slot.parent.replace(parent_index).is_some();
        if !replacing {
            self.links += 1;
        }
    }

    pub fn get(&self, child: &NodeKey) -> Option<&Node<'a>> {
        let parent = self.slot(*child)?.parent?;
        self.retained.get(parent.get() as usize - 1)
    }

    pub fn len(&self) -> usize {
        self.links
    }

    pub fn is_empty(&self) -> bool {
        self.links == 0
    }

    fn retain(&mut self, parent: Node<'a>) -> NonZeroU32 {
        let key = parent.key();
        if let Some(index) = self.slot_mut(key).retained {
            return index;
        }

        self.retained.push(parent);
        let index = u32::try_from(self.retained.len())
            .ok()
            .and_then(NonZeroU32::new)
            .expect("retained Babel parent count fits a nonzero u32");
        self.slot_mut(key).retained = Some(index);
        index
    }

    fn slot(&self, key: NodeKey) -> Option<&NodeSlot> {
        match key.role {
            Role::Primary => self.primary.get(key.node.index()),
            Role::Synthesized => self.synthesized.get(&key.node.raw().get()),
        }
    }

    fn slot_mut(&mut self, key: NodeKey) -> &mut NodeSlot {
        match key.role {
            Role::Primary => {
                let index = key.node.index();
                if index >= self.primary.len() {
                    self.primary.resize(index + 1, NodeSlot::default());
                }
                &mut self.primary[index]
            }
            Role::Synthesized => self.synthesized.entry(key.node.raw().get()).or_default(),
        }
    }
}
