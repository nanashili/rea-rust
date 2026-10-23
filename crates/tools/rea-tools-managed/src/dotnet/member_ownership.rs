//! First-match TypeDef owner per physical member row.
//!
//! Port of `src/dotnet/ManagedMemberOwnership.ts`. The per-facts, per-table
//! owner lookups the TS caches in a WeakMap are cached here on an explicit
//! inspection-scoped cache.

use std::cell::RefCell;
use std::collections::HashMap;

use super::failure::ManagedReaderFailure;
use super::layout::ManagedMetadataLayout;
use super::member_pointers::{MemberListRowLookupCache, member_list_row_lookup, member_list_table};
use super::type_member_lists::TypeMemberListFacts;

/// A computed owner lookup table (definition-list position -> owner row) plus
/// the row-position lookup used to translate physical rows.
struct OwnerTable {
    owners: Vec<i64>,
    row_lookup_cache: MemberListRowLookupCache,
    row_lookup: super::member_pointers::MemberListRowLookupHandle,
    definitions: i64,
    positions: i64,
}

/// Inspection-scoped cache of owner lookups by table (4 or 6).
#[derive(Default)]
pub struct MemberOwnershipCache {
    by_table: RefCell<HashMap<usize, Result<OwnerTable, ManagedReaderFailure>>>,
}

/// `memberDeclaringTypeRowLookup(bytes, layout, table, facts)`: build (or reuse)
/// the first-match owner table, then resolve a definition row to its owner.
pub fn member_declaring_type_row_lookup(
    cache: &MemberOwnershipCache,
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    table: usize,
    facts: &TypeMemberListFacts,
) -> Result<OwnerLookup, ManagedReaderFailure> {
    {
        let map = cache.by_table.borrow();
        if let Some(entry) = map.get(&table) {
            return match entry {
                Ok(_) => Ok(OwnerLookup { table }),
                Err(failure) => Err(failure.clone()),
            };
        }
    }
    let built = build_owner_table(bytes, layout, table, facts);
    match built {
        Ok(owner_table) => {
            cache.by_table.borrow_mut().insert(table, Ok(owner_table));
            Ok(OwnerLookup { table })
        }
        Err(failure) => {
            cache
                .by_table
                .borrow_mut()
                .insert(table, Err(failure.clone()));
            Err(failure)
        }
    }
}

fn build_owner_table(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    table: usize,
    facts: &TypeMemberListFacts,
) -> Result<OwnerTable, ManagedReaderFailure> {
    let row_lookup_cache = MemberListRowLookupCache::default();
    let row_lookup = member_list_row_lookup(&row_lookup_cache, bytes, layout, table)?;
    let positions = member_list_table(layout, table)
        .map(|t| t.row_count)
        .unwrap_or(0);
    let types = layout.table(2).map(|t| t.row_count).unwrap_or(0);
    layout.budget().reserve(
        (2 * positions + 3) * 4 + 256,
        layout.table(2).map(|t| t.offset as u64),
    )?;
    let positions_usize = (positions + 1) as usize;
    let mut owners = vec![0i64; positions_usize];
    // Union-find "next" skip list over positions 0..=positions+1.
    let mut next: Vec<i64> = (0..=(positions + 1)).collect();
    fn unowned(next: &mut [i64], position: i64) -> i64 {
        let mut root = position;
        while next[root as usize] != root {
            root = next[root as usize];
        }
        let mut p = position;
        while p != root {
            let following = next[p as usize];
            next[p as usize] = root;
            p = following;
        }
        root
    }
    for row in 1..=types {
        let entry = facts.entries.get((row - 1) as usize);
        let member_start = entry.map(|entry| {
            if table == 4 {
                &entry.field
            } else {
                &entry.method
            }
        });
        let start = member_start.and_then(|range| range.start.value);
        let end = member_start.and_then(|range| range.end);
        if let (Some(start), Some(end)) = (start, end) {
            let limit = end.min(positions + 1);
            let mut p = unowned(&mut next, start.min(positions + 1));
            while p < limit {
                owners[p as usize] = row;
                next[p as usize] = p + 1;
                p = unowned(&mut next, p + 1);
            }
        }
    }
    let definitions = layout.table(table).map(|t| t.row_count).unwrap_or(0);
    Ok(OwnerTable {
        owners,
        row_lookup_cache,
        row_lookup,
        definitions,
        positions,
    })
}

/// A handle resolving an owner through the inspection-scoped cache.
pub struct OwnerLookup {
    table: usize,
}

impl OwnerLookup {
    /// `(definitionRow) => ownerRow`.
    pub fn lookup(
        &self,
        cache: &MemberOwnershipCache,
        definition: i64,
    ) -> Result<i64, ManagedReaderFailure> {
        let map = cache.by_table.borrow();
        match map.get(&self.table) {
            Some(Ok(owner_table)) => {
                if definition < 1 || definition > owner_table.definitions {
                    return Ok(0);
                }
                let position = owner_table
                    .row_lookup
                    .lookup(&owner_table.row_lookup_cache, definition)?;
                if position < 0 || position > owner_table.positions {
                    return Ok(0);
                }
                Ok(owner_table
                    .owners
                    .get(position as usize)
                    .copied()
                    .unwrap_or(0))
            }
            Some(Err(failure)) => Err(failure.clone()),
            None => Ok(0),
        }
    }
}
