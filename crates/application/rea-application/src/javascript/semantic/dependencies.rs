//! Persistent dependency proofs for one semantic state's binding identities.

use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticDependencyProof {
    Empty,
    Leaf,
    Branch {
        zero: Option<Box<SemanticDependencyProof>>,
        one: Option<Box<SemanticDependencyProof>>,
    },
}

pub struct SemanticDependencyProofs {
    indices: HashMap<String, usize>,
    singletons: HashMap<String, SemanticDependencyProof>,
    height: usize,
}

impl SemanticDependencyProofs {
    pub fn new(bindings: impl IntoIterator<Item = String>) -> Self {
        let mut indices = HashMap::new();
        for binding in bindings {
            let index = indices.len();
            indices.entry(binding).or_insert(index);
        }
        let count = indices.len().max(1);
        let height = (usize::BITS - (count - 1).leading_zeros()) as usize;
        Self {
            indices,
            singletons: HashMap::new(),
            height,
        }
    }

    pub fn binding(&mut self, binding: &str) -> SemanticDependencyProof {
        if let Some(prior) = self.singletons.get(binding) {
            return prior.clone();
        }
        let index = self.index(binding);
        let mut proof = SemanticDependencyProof::Leaf;
        for bit in 0..self.height {
            let one = (index / 2usize.pow(bit as u32)) % 2 == 1;
            proof = if one {
                SemanticDependencyProof::Branch {
                    zero: None,
                    one: Some(Box::new(proof)),
                }
            } else {
                SemanticDependencyProof::Branch {
                    zero: Some(Box::new(proof)),
                    one: None,
                }
            };
        }
        self.singletons.insert(binding.to_owned(), proof.clone());
        proof
    }

    pub fn union(
        first: Option<&SemanticDependencyProof>,
        second: Option<&SemanticDependencyProof>,
    ) -> Option<SemanticDependencyProof> {
        let Some(first) = first else {
            return second.cloned();
        };
        let Some(second) = second else {
            return Some(first.clone());
        };
        if first == second {
            return Some(first.clone());
        }
        if matches!(first, SemanticDependencyProof::Leaf)
            || matches!(second, SemanticDependencyProof::Leaf)
        {
            return Some(SemanticDependencyProof::Leaf);
        }
        let (
            SemanticDependencyProof::Branch {
                zero: first_zero,
                one: first_one,
            },
            SemanticDependencyProof::Branch {
                zero: second_zero,
                one: second_one,
            },
        ) = (first, second)
        else {
            return Some(SemanticDependencyProof::Leaf);
        };
        let zero = Self::union(first_zero.as_deref(), second_zero.as_deref()).map(Box::new);
        let one = Self::union(first_one.as_deref(), second_one.as_deref()).map(Box::new);
        Some(SemanticDependencyProof::Branch { zero, one })
    }

    pub fn intersects(
        &self,
        proof: Option<&SemanticDependencyProof>,
        active: &HashMap<String, usize>,
    ) -> bool {
        active
            .keys()
            .any(|binding| proof.is_some_and(|proof| self.has(proof, binding)))
    }

    pub fn has(&self, proof: &SemanticDependencyProof, binding: &str) -> bool {
        let index = self.index(binding);
        let mut current = proof;
        for bit in (0..self.height).rev() {
            match current {
                SemanticDependencyProof::Empty => return false,
                SemanticDependencyProof::Leaf => return true,
                SemanticDependencyProof::Branch { zero, one } => {
                    current = if (index / 2usize.pow(bit as u32)) % 2 == 1 {
                        match one.as_deref() {
                            Some(next) => next,
                            None => return false,
                        }
                    } else {
                        match zero.as_deref() {
                            Some(next) => next,
                            None => return false,
                        }
                    };
                }
            }
        }
        matches!(current, SemanticDependencyProof::Leaf)
    }

    fn index(&self, binding: &str) -> usize {
        *self
            .indices
            .get(binding)
            .unwrap_or_else(|| panic!("Unindexed semantic dependency: {binding}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_track_transitive_union_and_active_intersection() {
        let mut proofs = SemanticDependencyProofs::new(["a".into(), "b".into(), "c".into()]);
        let a = proofs.binding("a");
        let c = proofs.binding("c");
        let union = SemanticDependencyProofs::union(Some(&a), Some(&c)).expect("union");
        assert!(proofs.has(&union, "a"));
        assert!(proofs.has(&union, "c"));
        assert!(!proofs.has(&union, "b"));
        let mut active = HashMap::new();
        active.insert("b".into(), 1);
        assert!(!proofs.intersects(Some(&union), &active));
        active.insert("c".into(), 2);
        assert!(proofs.intersects(Some(&union), &active));
    }
}
