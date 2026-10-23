//! TypeDef member-list pointer resolution.
//!
//! Port of `src/dotnet/ManagedMemberPointers.ts`. The pointer-row lookups are
//! cached per layout; here they are computed on demand and memoized by the
//! caller that owns the lifetime, matching the shared-owner intent without a
//! global WeakMap.

use std::cell::RefCell;
use std::collections::HashMap;

use super::bytes::{read_u16, read_u32};
use super::failure::{ManagedReaderFailure, managed_failure};
use super::layout::{ManagedMetadataLayout, MetadataTableLayout};

/// A field (4) or method (6) definition table.
pub type MemberTable = usize;

/// `memberListTable`: the nonempty pointer table when present, else the
/// definition table.
pub fn member_list_table<'a>(
    layout: &'a ManagedMetadataLayout,
    table: MemberTable,
) -> Option<&'a MetadataTableLayout> {
    let pointers = layout.table(table - 1);
    match pointers {
        Some(pointers) if pointers.row_count > 0 => Some(pointers),
        _ => layout.table(table),
    }
}

/// `memberListIndexSize`.
pub fn member_list_index_size(layout: &ManagedMetadataLayout, table: MemberTable) -> i64 {
    if layout.table_index_size(table - 1) == 4 || layout.table_index_size(table) == 4 {
        4
    } else {
        2
    }
}

/// `validatedMemberListStart`.
pub fn validated_member_list_start(start: i64, table: Option<&MetadataTableLayout>) -> Option<i64> {
    let total = table.map(|table| table.row_count).unwrap_or(0);
    if start >= 1 && start <= total + 1 {
        Some(start)
    } else {
        None
    }
}

/// Pointer-table row positions by definition row. Tables without pointer
/// rows resolve by identity through [`MemberListRowLookupHandle::Identity`].
#[derive(Clone)]
pub struct MemberListRowLookup {
    positions: Vec<i64>,
    pointer_name: String,
    pointer_offset: i64,
}

impl MemberListRowLookup {
    /// Resolve a physical definition row to its list position.
    pub fn lookup(&self, definition: i64) -> Result<i64, ManagedReaderFailure> {
        let position = self
            .positions
            .get(definition as usize)
            .copied()
            .unwrap_or(0);
        if position == 0 {
            Err(managed_failure(
                "invalid-row",
                format!("metadata.{}", self.pointer_name),
                format!(
                    "Definition row {definition} has no pointer row identifying its declaring type"
                ),
                Some(self.pointer_offset as u64),
            ))
        } else {
            Ok(position)
        }
    }
}

/// Per-layout cache of member-list row lookups, by table. Replaces the TS
/// `WeakMap<ManagedMetadataLayout, ...>` with an explicit cache owned by the
/// inspection facts that borrow the layout.
#[derive(Default)]
pub struct MemberListRowLookupCache {
    by_table: RefCell<HashMap<MemberTable, Result<MemberListRowLookup, ManagedReaderFailure>>>,
}

/// `memberListRowLookup(bytes, layout, table)` with its cached failure semantics.
pub fn member_list_row_lookup(
    cache: &MemberListRowLookupCache,
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    table: MemberTable,
) -> Result<MemberListRowLookupHandle, ManagedReaderFailure> {
    let pointers = layout.table(table - 1);
    let pointers = match pointers {
        Some(pointers) if pointers.row_count > 0 => pointers.clone(),
        _ => return Ok(MemberListRowLookupHandle::Identity),
    };

    {
        let map = cache.by_table.borrow();
        if let Some(entry) = map.get(&table) {
            return match entry {
                Ok(_) => Ok(MemberListRowLookupHandle::Cached(table)),
                Err(failure) => Err(failure.clone()),
            };
        }
    }

    let definition_count = layout.table(table).map(|t| t.row_count).unwrap_or(0);
    // Reserve retained index storage and bookkeeping before allocating.
    if let Err(failure) = layout.budget().reserve(
        (definition_count + 1) * 4 + 256,
        Some(pointers.offset as u64),
    ) {
        return Err(failure);
    }

    let built = build_positions(bytes, layout, table, &pointers, definition_count);
    match &built {
        Ok(lookup) => {
            cache
                .by_table
                .borrow_mut()
                .insert(table, Ok(lookup.clone()));
            Ok(MemberListRowLookupHandle::Cached(table))
        }
        Err(failure) => {
            cache
                .by_table
                .borrow_mut()
                .insert(table, Err(failure.clone()));
            Err(failure.clone())
        }
    }
}

fn build_positions(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    table: MemberTable,
    pointers: &MetadataTableLayout,
    definition_count: i64,
) -> Result<MemberListRowLookup, ManagedReaderFailure> {
    let mut positions = vec![0i64; (definition_count + 1) as usize];
    let width = layout.table_index_size(table);
    for row in 1..=pointers.row_count {
        let offset = pointers.offset + (row - 1) * pointers.row_size;
        let definition = if width == 2 {
            read_u16(bytes, offset as usize)
                .map_err(|_| pointer_internal(pointers))
                .map(|v| v as i64)?
        } else {
            read_u32(bytes, offset as usize)
                .map_err(|_| pointer_internal(pointers))
                .map(|v| v as i64)?
        };
        if definition == 0 || definition > definition_count {
            return Err(managed_failure(
                "invalid-row",
                format!("metadata.{}", pointers.name),
                format!("Pointer row {row} names an out-of-range definition row {definition}"),
                Some(offset as u64),
            ));
        }
        if positions[definition as usize] != 0 {
            return Err(managed_failure(
                "invalid-row",
                format!("metadata.{}", pointers.name),
                format!(
                    "Definition row {definition} has more than one pointer row; its declaring type is ambiguous"
                ),
                Some(offset as u64),
            ));
        }
        positions[definition as usize] = row;
    }
    Ok(MemberListRowLookup {
        positions,
        pointer_name: pointers.name.clone(),
        pointer_offset: pointers.offset,
    })
}

fn pointer_internal(pointers: &MetadataTableLayout) -> ManagedReaderFailure {
    managed_failure(
        "invalid-row",
        format!("metadata.{}", pointers.name),
        "Pointer row read left the artifact byte range",
        Some(pointers.offset as u64),
    )
}

/// A handle that resolves against the cache (avoids returning a borrow).
pub enum MemberListRowLookupHandle {
    Identity,
    Cached(MemberTable),
}

impl MemberListRowLookupHandle {
    pub fn lookup(
        &self,
        cache: &MemberListRowLookupCache,
        definition: i64,
    ) -> Result<i64, ManagedReaderFailure> {
        match self {
            MemberListRowLookupHandle::Identity => Ok(definition),
            MemberListRowLookupHandle::Cached(table) => {
                let map = cache.by_table.borrow();
                match map.get(table) {
                    Some(Ok(lookup)) => lookup.lookup(definition),
                    Some(Err(failure)) => Err(failure.clone()),
                    None => Ok(definition),
                }
            }
        }
    }
}
