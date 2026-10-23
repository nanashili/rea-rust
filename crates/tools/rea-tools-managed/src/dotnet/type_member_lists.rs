//! TypeDef field/method list coordinates with monotonicity validation.
//!
//! Port of `src/dotnet/ManagedTypeMemberLists.ts`.

use std::collections::BTreeSet;

use super::failure::{ManagedParseIssue, ManagedReaderFailure};
use super::heaps::{metadata_row_cursor, metadata_token};
use super::layout::ManagedMetadataLayout;
use super::member_pointers::{
    member_list_index_size, member_list_table, validated_member_list_start,
};

/// One member-list start: raw value, validated value, and column offset.
#[derive(Clone)]
pub struct TypeMemberListStart {
    pub raw: i64,
    pub value: Option<i64>,
    pub offset: i64,
}

/// A member-list range: start plus the exclusive end (next start or sentinel).
#[derive(Clone)]
pub struct TypeMemberListRange {
    pub start: TypeMemberListStart,
    pub end: Option<i64>,
}

/// Field and method ranges for one TypeDef row.
#[derive(Clone)]
pub struct TypeMemberListEntry {
    pub field: TypeMemberListRange,
    pub method: TypeMemberListRange,
}

/// Parsed TypeDef list coordinates and the issues observed building them.
pub struct TypeMemberListFacts {
    pub entries: Vec<TypeMemberListEntry>,
    pub issues: Vec<ManagedParseIssue>,
}

struct RawRow {
    field: TypeMemberListStart,
    method: TypeMemberListStart,
}

/// `readTypeMemberListFacts(bytes, layout)`.
pub fn read_type_member_list_facts(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
) -> Result<TypeMemberListFacts, ManagedReaderFailure> {
    let fields = member_list_table(layout, 4).cloned();
    let methods = member_list_table(layout, 6).cloned();
    let mut rows: Vec<RawRow> = Vec::new();
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let types = layout.table(2).cloned();
    let type_count = types.as_ref().map(|t| t.row_count).unwrap_or(0);
    layout.budget().reserve(
        type_count * 512 + 256,
        types.as_ref().map(|t| t.offset as u64),
    )?;
    let field_index_size = member_list_index_size(layout, 4);
    let method_index_size = member_list_index_size(layout, 6);
    for row in 1..=type_count {
        let mut cursor = metadata_row_cursor(bytes, layout, 2, row)?;
        cursor.read_u32()?;
        cursor.read_index(layout.string_index_size)?;
        cursor.read_index(layout.string_index_size)?;
        cursor.read_index(layout.coded_index_size("TypeDefOrRef"))?;
        let field_offset = cursor.offset();
        let field_raw = cursor.read_index(field_index_size)? as i64;
        let method_offset = cursor.offset();
        let method_raw = cursor.read_index(method_index_size)? as i64;
        let entry = RawRow {
            field: TypeMemberListStart {
                raw: field_raw,
                value: validated_member_list_start(field_raw, fields.as_ref()),
                offset: field_offset,
            },
            method: TypeMemberListStart {
                raw: method_raw,
                value: validated_member_list_start(method_raw, methods.as_ref()),
                offset: method_offset,
            },
        };
        for (name, start, table) in [
            ("FieldList", &entry.field, fields.as_ref()),
            ("MethodList", &entry.method, methods.as_ref()),
        ] {
            if start.value.is_none() {
                layout.budget().reserve(512, Some(start.offset as u64))?;
                issues.push(ManagedParseIssue {
                    code: "invalid-row",
                    scope: format!("metadata.TypeDef:{}", metadata_token(2, row)),
                    offset: Some(start.offset as u64),
                    detail: format!(
                        "TypeDef {name} start {} is outside the one-based list range 1..{}",
                        start.raw,
                        table.map(|t| t.row_count).unwrap_or(0) + 1
                    ),
                });
            }
        }
        rows.push(entry);
    }

    let mut nonmonotonic_fields: BTreeSet<usize> = BTreeSet::new();
    let mut nonmonotonic_methods: BTreeSet<usize> = BTreeSet::new();
    for index in 0..rows.len().saturating_sub(1) {
        let (before_slice, after_slice) = rows.split_at(index + 1);
        let current = &before_slice[index];
        let next = &after_slice[0];
        for selector in 0..2 {
            let (name, before, after, affected) = if selector == 0 {
                (
                    "FieldList",
                    &current.field,
                    &next.field,
                    &mut nonmonotonic_fields,
                )
            } else {
                (
                    "MethodList",
                    &current.method,
                    &next.method,
                    &mut nonmonotonic_methods,
                )
            };
            if let (Some(before_value), Some(after_value)) = (before.value, after.value) {
                if after_value < before_value {
                    layout.budget().reserve(512, Some(after.offset as u64))?;
                    affected.insert(index);
                    affected.insert(index + 1);
                    issues.push(ManagedParseIssue {
                        code: "invalid-row",
                        scope: format!("metadata.TypeDef:{}", metadata_token(2, index as i64 + 2)),
                        offset: Some(after.offset as u64),
                        detail: format!(
                            "TypeDef {name} start {} decreases from preceding start {}; adjacent member ranges are unknown",
                            after.raw, before.raw
                        ),
                    });
                }
            }
        }
    }

    let field_row_count = fields.as_ref().map(|t| t.row_count).unwrap_or(0);
    let method_row_count = methods.as_ref().map(|t| t.row_count).unwrap_or(0);
    let total = rows.len();
    let mut entries: Vec<TypeMemberListEntry> = Vec::with_capacity(total);
    for (index, entry) in rows.iter().enumerate() {
        let next = rows.get(index + 1);
        let field_end = match next {
            None => Some(field_row_count + 1),
            Some(next) => {
                if nonmonotonic_fields.contains(&index)
                    || nonmonotonic_fields.contains(&(index + 1))
                {
                    None
                } else {
                    next.field.value
                }
            }
        };
        let method_end = match next {
            None => Some(method_row_count + 1),
            Some(next) => {
                if nonmonotonic_methods.contains(&index)
                    || nonmonotonic_methods.contains(&(index + 1))
                {
                    None
                } else {
                    next.method.value
                }
            }
        };
        entries.push(TypeMemberListEntry {
            field: TypeMemberListRange {
                start: TypeMemberListStart {
                    raw: entry.field.raw,
                    value: if nonmonotonic_fields.contains(&index) {
                        None
                    } else {
                        entry.field.value
                    },
                    offset: entry.field.offset,
                },
                end: field_end,
            },
            method: TypeMemberListRange {
                start: TypeMemberListStart {
                    raw: entry.method.raw,
                    value: if nonmonotonic_methods.contains(&index) {
                        None
                    } else {
                        entry.method.value
                    },
                    offset: entry.method.offset,
                },
                end: method_end,
            },
        });
    }
    Ok(TypeMemberListFacts { entries, issues })
}
