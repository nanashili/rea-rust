//! NestedClass facts shared by declaring types and signature operands.
//!
//! Port of `src/dotnet/ManagedTypeNesting.ts`.

use std::collections::BTreeMap;

use super::failure::{
    ManagedParseIssue, ReadError, ReadResult, managed_failure, read_managed_value,
};
use super::heaps::{metadata_row_cursor, metadata_token};
use super::layout::ManagedMetadataLayout;

/// Parsed NestedClass nesting: nested row -> enclosing row, and completeness.
pub struct ManagedTypeNesting {
    pub enclosing: BTreeMap<i64, i64>,
    pub complete: bool,
}

/// `readManagedTypeNesting(bytes, layout, issues)`.
pub fn read_managed_type_nesting(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<ManagedTypeNesting> {
    let initial_issues = issues.len();
    let type_count = layout.table(2).map(|t| t.row_count).unwrap_or(0);
    let mut enclosing: BTreeMap<i64, i64> = BTreeMap::new();
    let nested_rows = layout.table(41).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=nested_rows {
        read_managed_value(
            || -> ReadResult<()> {
                let mut cursor = metadata_row_cursor(bytes, layout, 41, row)?;
                let nested = cursor.read_index(layout.table_index_size(2))? as i64;
                let outer = cursor.read_index(layout.table_index_size(2))? as i64;
                if nested < 1
                    || outer < 1
                    || nested > type_count
                    || outer > type_count
                    || nested == outer
                    || enclosing.contains_key(&nested)
                {
                    return Err(ReadError::Reader(managed_failure(
                        "invalid-row",
                        format!("metadata.NestedClass:{}", metadata_token(41, row)),
                        format!(
                            "NestedClass requires a unique nested type and distinct existing enclosing type; observed {nested} -> {outer}"
                        ),
                        Some(cursor.start as u64),
                    )));
                }
                layout.budget().reserve(128, Some(cursor.start as u64))?;
                enclosing.insert(nested, outer);
                Ok(())
            },
            issues,
        )?;
    }
    let complete = issues.len() == initial_issues;
    Ok(ManagedTypeNesting {
        enclosing,
        complete,
    })
}
