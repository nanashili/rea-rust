use std::collections::HashMap;
use std::mem::size_of;

use crate::javascript::ast::NodeKey;

use super::super::value_types::SemanticValue;
use super::independent_cache::{MAX_CACHE_BYTES, MAX_CACHE_ENTRIES, semantic_value_bytes};

#[derive(Default)]
pub(super) struct CapturedBindingCache {
    entries: HashMap<NodeKey, HashMap<String, CapturedBindingValue>>,
    entry_count: usize,
    bytes: usize,
}

struct CapturedBindingValue {
    value: SemanticValue,
    estimated_bytes: usize,
}

impl CapturedBindingCache {
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(super) fn get(&self, capture: NodeKey, binding: &str) -> Option<&SemanticValue> {
        self.entries
            .get(&capture)
            .and_then(|bindings| bindings.get(binding))
            .map(|entry| &entry.value)
    }

    pub(super) fn admit(&mut self, capture: NodeKey, binding: &str, value: SemanticValue) {
        let estimated_bytes = captured_binding_bytes(&value, binding);
        if estimated_bytes > MAX_CACHE_BYTES {
            return;
        }

        let previous = self
            .entries
            .get_mut(&capture)
            .and_then(|values| values.remove(binding));
        if let Some(previous) = previous {
            self.bytes = self.bytes.saturating_sub(previous.estimated_bytes);
            self.entry_count = self.entry_count.saturating_sub(1);
        }

        if self.entry_count >= MAX_CACHE_ENTRIES
            || self.bytes.saturating_add(estimated_bytes) > MAX_CACHE_BYTES
        {
            self.clear();
        }

        self.bytes = self.bytes.saturating_add(estimated_bytes);
        self.entries.entry(capture).or_default().insert(
            binding.to_owned(),
            CapturedBindingValue {
                value,
                estimated_bytes,
            },
        );
        self.entry_count += 1;
    }
}

fn captured_binding_bytes(value: &SemanticValue, binding: &str) -> usize {
    size_of::<CapturedBindingValue>()
        .saturating_add(binding.len())
        .saturating_add(size_of::<NodeKey>())
        .saturating_add(semantic_value_bytes(value))
}
