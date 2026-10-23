//! TypeRef source tuples and ResolutionScope chain validation.
//!
//! Port of `src/dotnet/ManagedTypeReferences.ts`. The TS returns a closure over
//! shared memo maps; here a `ManagedTypeReferences` struct owns those maps and
//! exposes `lookup`.

use std::collections::HashMap;

use super::failure::{ManagedParseIssue, ReadResult, read_managed_value};
use super::heaps::{
    metadata_coded_token_invalid_reason, metadata_row_cursor, metadata_token, read_metadata_string,
};
use super::layout::{ManagedMetadataLayout, metadata_row_offset};

/// One resolved TypeRef: namespace/name, optional enclosing row, scope validity.
#[derive(Clone)]
pub struct ManagedTypeReference {
    pub namespace: String,
    pub name: String,
    pub enclosing_row: Option<i64>,
    pub scope_valid: bool,
}

#[derive(Clone)]
struct TypeReferenceRow {
    name_index: u32,
    namespace_index: u32,
    enclosing_row: Option<i64>,
    scope_valid: bool,
}

/// Owns the per-inspection TypeRef memo maps (`rows`, `names`, `checked`).
pub struct ManagedTypeReferences {
    rows: HashMap<i64, Option<TypeReferenceRow>>,
    names: HashMap<i64, Option<ManagedTypeReference>>,
    checked: HashMap<i64, bool>,
}

impl ManagedTypeReferences {
    pub fn new() -> Self {
        Self {
            rows: HashMap::new(),
            names: HashMap::new(),
            checked: HashMap::new(),
        }
    }

    fn read(
        &mut self,
        bytes: &[u8],
        layout: &ManagedMetadataLayout,
        issues: &mut Vec<ManagedParseIssue>,
        row: i64,
    ) -> ReadResult<Option<TypeReferenceRow>> {
        if let Some(cached) = self.rows.get(&row) {
            return Ok(cached.clone());
        }
        layout.budget().reserve(384, None)?;
        // The closure returns both the parsed row and the optional invalid-row
        // issue so `issues` is borrowed only once (by `read_managed_value`),
        // matching the TS which pushes the issue during the read.
        let value = read_managed_value(
            || -> ReadResult<(TypeReferenceRow, Option<ManagedParseIssue>)> {
                let mut cursor = metadata_row_cursor(bytes, layout, 1, row)?;
                let raw = cursor.read_index(layout.coded_index_size("ResolutionScope"))?;
                let reason = metadata_coded_token_invalid_reason(
                    raw,
                    2,
                    &[Some(0), Some(26), Some(35), Some(1)],
                    &layout.row_counts,
                );
                let issue = reason.as_ref().map(|reason| ManagedParseIssue {
                    code: "invalid-row",
                    scope: format!("metadata.TypeRef:{}", metadata_token(1, row)),
                    offset: Some(cursor.start as u64),
                    detail: format!(
                        "TypeRef ResolutionScope coded index 0x{:x} is invalid: {reason}",
                        raw
                    ),
                });
                let name_index = cursor.read_index(layout.string_index_size)?;
                let namespace_index = cursor.read_index(layout.string_index_size)?;
                Ok((
                    TypeReferenceRow {
                        name_index,
                        namespace_index,
                        enclosing_row: if raw != 0 && (raw & 3) == 3 {
                            Some((raw >> 2) as i64)
                        } else {
                            None
                        },
                        scope_valid: reason.is_none(),
                    },
                    issue,
                ))
            },
            issues,
        )?;
        let value = match value {
            Some((row_value, issue)) => {
                if let Some(issue) = issue {
                    issues.push(issue);
                }
                Some(row_value)
            }
            None => None,
        };
        self.rows.insert(row, value.clone());
        Ok(value)
    }

    fn validate(
        &mut self,
        bytes: &[u8],
        layout: &ManagedMetadataLayout,
        issues: &mut Vec<ManagedParseIssue>,
        row: i64,
    ) -> ReadResult<bool> {
        if let Some(prior) = self.checked.get(&row) {
            return Ok(*prior);
        }
        let mut path: Vec<i64> = Vec::new();
        let mut seen: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
        let mut current: Option<i64> = Some(row);
        let mut valid = true;
        while let Some(current_row) = current {
            if let Some(known) = self.checked.get(&current_row) {
                valid = *known;
                break;
            }
            if seen.contains(&current_row) {
                issues.push(ManagedParseIssue {
                    code: "invalid-row",
                    scope: format!("metadata.TypeRef:{}", metadata_token(1, current_row)),
                    offset: Some(metadata_row_offset(layout, 1, current_row)? as u64),
                    detail: "TypeRef ResolutionScope chain contains a cycle".to_string(),
                });
                valid = false;
                break;
            }
            seen.insert(current_row);
            path.push(current_row);
            let value = self.read(bytes, layout, issues, current_row)?;
            match value {
                Some(value) if value.scope_valid => {
                    current = value.enclosing_row;
                }
                _ => {
                    valid = false;
                    break;
                }
            }
        }
        for visited in path {
            self.checked.insert(visited, valid);
        }
        Ok(valid)
    }

    /// `(row) => ManagedTypeReference | null`.
    pub fn lookup(
        &mut self,
        bytes: &[u8],
        layout: &ManagedMetadataLayout,
        issues: &mut Vec<ManagedParseIssue>,
        row: i64,
    ) -> ReadResult<Option<ManagedTypeReference>> {
        if let Some(cached) = self.names.get(&row) {
            return Ok(cached.clone());
        }
        let value = self.read(bytes, layout, issues, row)?;
        let value = match value {
            Some(value) => value,
            None => return Ok(None),
        };
        let scope_valid = self.validate(bytes, layout, issues, row)?;
        layout.budget().reserve(128, None)?;
        let named = read_managed_value(
            || -> ReadResult<ManagedTypeReference> {
                Ok(ManagedTypeReference {
                    namespace: read_metadata_string(
                        bytes,
                        layout,
                        value.namespace_index,
                        layout.strings.size,
                    )?,
                    name: read_metadata_string(
                        bytes,
                        layout,
                        value.name_index,
                        layout.strings.size,
                    )?,
                    enclosing_row: value.enclosing_row,
                    scope_valid,
                })
            },
            issues,
        )?;
        self.names.insert(row, named.clone());
        Ok(named)
    }
}

impl Default for ManagedTypeReferences {
    fn default() -> Self {
        Self::new()
    }
}
