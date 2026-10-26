//! Persistent dependency proofs for one semantic state's binding identities.

use std::collections::HashMap;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticDependencyProof {
    Empty,
    Leaf,
    Branch {
        zero: Option<Rc<SemanticDependencyProof>>,
        one: Option<Rc<SemanticDependencyProof>>,
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
                    one: Some(Rc::new(proof)),
                }
            } else {
                SemanticDependencyProof::Branch {
                    zero: Some(Rc::new(proof)),
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
        if Self::has_same_shape(first, second) {
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
        let zero = Self::union_branch(first_zero.as_ref(), second_zero.as_ref());
        let one = Self::union_branch(first_one.as_ref(), second_one.as_ref());
        Some(SemanticDependencyProof::Branch { zero, one })
    }

    fn has_same_shape(first: &SemanticDependencyProof, second: &SemanticDependencyProof) -> bool {
        match (first, second) {
            (SemanticDependencyProof::Empty, SemanticDependencyProof::Empty)
            | (SemanticDependencyProof::Leaf, SemanticDependencyProof::Leaf) => true,
            (
                SemanticDependencyProof::Branch {
                    zero: first_zero,
                    one: first_one,
                },
                SemanticDependencyProof::Branch {
                    zero: second_zero,
                    one: second_one,
                },
            ) => {
                Self::same_child(first_zero, second_zero) && Self::same_child(first_one, second_one)
            }
            _ => false,
        }
    }

    fn same_child(
        first: &Option<Rc<SemanticDependencyProof>>,
        second: &Option<Rc<SemanticDependencyProof>>,
    ) -> bool {
        match (first, second) {
            (None, None) => true,
            (Some(first), Some(second)) => Rc::ptr_eq(first, second),
            _ => false,
        }
    }

    fn union_branch(
        first: Option<&Rc<SemanticDependencyProof>>,
        second: Option<&Rc<SemanticDependencyProof>>,
    ) -> Option<Rc<SemanticDependencyProof>> {
        match (first, second) {
            (None, None) => None,
            (Some(first), None) => Some(Rc::clone(first)),
            (None, Some(second)) => Some(Rc::clone(second)),
            (Some(first), Some(second)) if Rc::ptr_eq(first, second) => Some(Rc::clone(first)),
            (Some(first), Some(second)) => {
                Self::union(Some(first.as_ref()), Some(second.as_ref())).map(Rc::new)
            }
        }
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

    #[test]
    fn cloned_deep_proofs_share_immutable_nodes() {
        let bindings = (0..4096)
            .map(|index| format!("binding-{index}"))
            .collect::<Vec<_>>();
        let mut proofs = SemanticDependencyProofs::new(bindings);
        let original = proofs.binding("binding-2048");
        let cloned = original.clone();

        assert_eq!(original, cloned);
        assert_shared_nodes(&original, &cloned);

        let union = SemanticDependencyProofs::union(Some(&original), None).expect("union");
        assert_eq!(union, original);
        assert_shared_nodes(&original, &union);
        assert!(proofs.has(&union, "binding-2048"));
        assert!(!proofs.has(&union, "binding-2049"));
    }

    #[test]
    fn overlapping_union_reuses_unchanged_branch_and_preserves_inputs() {
        let mut proofs = SemanticDependencyProofs::new(
            (0..16)
                .map(|index| format!("binding-{index}"))
                .collect::<Vec<_>>(),
        );
        let first = proofs.binding("binding-0");
        let second = proofs.binding("binding-1");
        let distant = proofs.binding("binding-8");
        let left = SemanticDependencyProofs::union(Some(&first), Some(&second)).expect("left");
        let right = SemanticDependencyProofs::union(Some(&first), Some(&distant)).expect("right");
        let merged = SemanticDependencyProofs::union(Some(&left), Some(&right)).expect("merged");

        assert!(proofs.has(&merged, "binding-0"));
        assert!(proofs.has(&merged, "binding-1"));
        assert!(proofs.has(&merged, "binding-8"));
        assert!(!proofs.has(&left, "binding-8"));
        assert!(!proofs.has(&right, "binding-1"));

        let (
            SemanticDependencyProof::Branch {
                one: Some(right_one),
                ..
            },
            SemanticDependencyProof::Branch {
                one: Some(merged_one),
                ..
            },
        ) = (&right, &merged)
        else {
            panic!("distant dependency should occupy the high branch");
        };
        assert!(Rc::ptr_eq(right_one, merged_one));
    }

    fn assert_shared_nodes(left: &SemanticDependencyProof, right: &SemanticDependencyProof) {
        match (left, right) {
            (SemanticDependencyProof::Empty, SemanticDependencyProof::Empty)
            | (SemanticDependencyProof::Leaf, SemanticDependencyProof::Leaf) => {}
            (
                SemanticDependencyProof::Branch {
                    zero: left_zero,
                    one: left_one,
                },
                SemanticDependencyProof::Branch {
                    zero: right_zero,
                    one: right_one,
                },
            ) => {
                assert_options_share_nodes(left_zero, right_zero);
                assert_options_share_nodes(left_one, right_one);
            }
            _ => panic!("proof clones changed shape"),
        }
    }

    fn assert_options_share_nodes(
        left: &Option<Rc<SemanticDependencyProof>>,
        right: &Option<Rc<SemanticDependencyProof>>,
    ) {
        match (left, right) {
            (None, None) => {}
            (Some(left), Some(right)) => {
                assert!(Rc::ptr_eq(left, right));
                assert_shared_nodes(left, right);
            }
            _ => panic!("proof clones changed branch shape"),
        }
    }
}
