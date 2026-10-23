//! A string-keyed map with JavaScript `Map` iteration order: replacing a
//! value keeps its position, deleting then setting appends. Every write
//! assigns a new version, standing in for the object identity the TS
//! owners compare.
use std::collections::{BTreeMap, HashMap};

pub(super) struct OrderedMap<V> {
    positions: HashMap<String, (u64, u64)>,
    entries: BTreeMap<u64, V>,
    next: u64,
}

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self {
            positions: HashMap::new(),
            entries: BTreeMap::new(),
            next: 0,
        }
    }
}

impl<V> OrderedMap<V> {
    fn bump(&mut self) -> u64 {
        self.next += 1;
        self.next
    }
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn get(&self, key: &str) -> Option<&V> {
        self.positions
            .get(key)
            .and_then(|(position, _)| self.entries.get(position))
    }
    pub(super) fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        let position = self.positions.get(key)?.0;
        self.entries.get_mut(&position)
    }
    /// The identity of the current value, if any.
    pub(super) fn version(&self, key: &str) -> Option<u64> {
        self.positions.get(key).map(|(_, version)| *version)
    }
    pub(super) fn set(&mut self, key: &str, value: V) {
        let version = self.bump();
        match self.positions.get_mut(key) {
            Some((position, current)) => {
                *current = version;
                self.entries.insert(*position, value);
            }
            None => {
                let position = version;
                self.positions.insert(key.to_owned(), (position, version));
                self.entries.insert(position, value);
            }
        }
    }
    /// Record an in-place replacement (`map.set(key, { ...current })`).
    pub(super) fn touch(&mut self, key: &str) {
        let version = self.bump();
        if let Some((_, current)) = self.positions.get_mut(key) {
            *current = version;
        }
    }
    pub(super) fn remove(&mut self, key: &str) {
        if let Some((position, _)) = self.positions.remove(key) {
            self.entries.remove(&position);
        }
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values()
    }
}
