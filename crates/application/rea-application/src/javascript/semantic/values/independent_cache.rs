use std::collections::HashMap;
use std::mem::size_of;

use super::super::dependencies::SemanticDependencyProof;
use super::super::value_types::{JsString, Primitive, Property, SemanticValue};
use super::Memoized;

// This bounds the estimated payload retained by the derived memo. Evicted
// values are recomputed and do not change semantic coverage or classification.
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_CACHE_ENTRIES: usize = 4096;

#[derive(Clone)]
pub(super) struct IndependentBindingValue {
    pub(super) evaluated: Memoized<SemanticValue>,
    pub(super) depth: usize,
    estimated_bytes: usize,
}

#[derive(Default)]
pub(super) struct IndependentBindingCache {
    entries: HashMap<String, IndependentBindingValue>,
    bytes: usize,
}

impl IndependentBindingCache {
    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }

    pub(super) fn get(&self, binding_id: &str) -> Option<&IndependentBindingValue> {
        self.entries.get(binding_id)
    }

    pub(super) fn admit(
        &mut self,
        binding_id: &str,
        evaluated: &Memoized<SemanticValue>,
        depth: usize,
    ) {
        let estimated_bytes = independent_binding_bytes(binding_id, evaluated);
        if estimated_bytes > MAX_CACHE_BYTES {
            return;
        }

        if let Some(previous) = self.entries.remove(binding_id) {
            self.bytes = self.bytes.saturating_sub(previous.estimated_bytes);
        }

        if self.entries.len() >= MAX_CACHE_ENTRIES
            || self.bytes.saturating_add(estimated_bytes) > MAX_CACHE_BYTES
        {
            self.clear();
        }

        self.bytes = self.bytes.saturating_add(estimated_bytes);
        self.entries.insert(
            binding_id.to_owned(),
            IndependentBindingValue {
                evaluated: evaluated.clone(),
                depth,
                estimated_bytes,
            },
        );
    }
}

fn independent_binding_bytes(binding_id: &str, evaluated: &Memoized<SemanticValue>) -> usize {
    let mut bytes = size_of::<IndependentBindingValue>().saturating_add(binding_id.len());
    bytes = bounded_cache_bytes_add(bytes, semantic_value_bytes(&evaluated.value));
    if bytes > MAX_CACHE_BYTES {
        return bytes;
    }
    bounded_cache_bytes_add(
        bytes,
        dependency_proof_bytes(evaluated.dependencies.as_ref()),
    )
}

fn bounded_cache_bytes_add(current: usize, additional: usize) -> usize {
    current.saturating_add(additional).min(MAX_CACHE_BYTES + 1)
}

fn semantic_value_bytes(value: &SemanticValue) -> usize {
    let inline = size_of::<SemanticValue>();
    match value {
        SemanticValue::Literal { value } => inline.saturating_add(primitive_bytes(value)),
        SemanticValue::Union { values } => {
            let mut bytes =
                inline.saturating_add(values.capacity().saturating_mul(size_of::<Primitive>()));
            if bytes > MAX_CACHE_BYTES {
                return bytes;
            }
            for value in values {
                bytes = bounded_cache_bytes_add(bytes, primitive_bytes(value));
                if bytes > MAX_CACHE_BYTES {
                    break;
                }
            }
            bytes
        }
        SemanticValue::Object { properties, .. } => {
            inline.saturating_add(property_list_bytes(properties, properties.capacity()))
        }
        SemanticValue::Array { items, .. } => {
            inline.saturating_add(property_list_bytes(items, items.capacity()))
        }
        SemanticValue::Unknown { reason, .. }
        | SemanticValue::Ambiguous { reason, .. }
        | SemanticValue::Cycle { reason, .. } => inline.saturating_add(js_string_bytes(reason)),
    }
}

fn primitive_bytes(value: &Primitive) -> usize {
    match value {
        Primitive::String(value) => js_string_bytes(value),
        Primitive::Number(_) | Primitive::Boolean(_) | Primitive::Null => 0,
    }
}

fn js_string_bytes(value: &JsString) -> usize {
    let units = value.len();
    if units == 0 {
        0
    } else {
        // JsString may retain source UTF-8, lazy UTF-16, cached UTF-8, and
        // Arc/OnceLock metadata. This is an estimated payload charge.
        128usize.saturating_add(units.saturating_mul(10))
    }
}

fn property_list_bytes(properties: &[Property], capacity: usize) -> usize {
    let mut bytes = capacity.saturating_mul(size_of::<Property>());
    if bytes > MAX_CACHE_BYTES {
        return bytes;
    }
    for property in properties {
        bytes = bounded_cache_bytes_add(bytes, size_of::<Property>());
        bytes = bounded_cache_bytes_add(bytes, js_string_bytes(&property.name));
        bytes = bounded_cache_bytes_add(bytes, semantic_value_bytes(&property.value));
        if bytes > MAX_CACHE_BYTES {
            break;
        }
    }
    bytes
}

fn dependency_proof_bytes(proof: Option<&SemanticDependencyProof>) -> usize {
    match proof {
        None => 0,
        Some(proof) => dependency_proof_node_bytes(proof, false),
    }
}

fn dependency_proof_node_bytes(proof: &SemanticDependencyProof, owned_by_rc: bool) -> usize {
    let mut bytes = size_of::<SemanticDependencyProof>();
    if owned_by_rc {
        bytes = bounded_cache_bytes_add(bytes, size_of::<usize>() * 2);
    }
    if bytes > MAX_CACHE_BYTES {
        return bytes;
    }

    let SemanticDependencyProof::Branch { zero, one } = proof else {
        return bytes;
    };
    for child in [zero.as_deref(), one.as_deref()].into_iter().flatten() {
        bytes = bounded_cache_bytes_add(bytes, dependency_proof_node_bytes(child, true));
        if bytes > MAX_CACHE_BYTES {
            break;
        }
    }
    bytes
}
