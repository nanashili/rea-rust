//! Namespace-qualified names for TypeDef/TypeRef/generic-instantiation tokens.
//!
//! Port of `src/dotnet/ManagedTypeNames.ts`. Each token is named once; a
//! TypeSpec that is not a generic instantiation of a TypeDef/TypeRef stays
//! unknown, and unreadable rows or blobs are recorded to `issues` and stay
//! null, except that a TypeRef with an invalid ResolutionScope keeps its
//! readable name.

use std::collections::HashMap;

use super::failure::{ManagedParseIssue, ReadError, ReadResult, managed_failure};
use super::heaps::{metadata_row_cursor, metadata_token, read_metadata_blob};
use super::layout::{ManagedMetadataLayout, metadata_row_offset};
use super::member_core::{TypeRange, full_name, read_compressed, spec_signature};
use super::type_references::ManagedTypeReferences;

/// Memoized token -> namespace-qualified name lookup.
pub struct TypeNameLookup {
    names: HashMap<String, Option<String>>,
}

impl Default for TypeNameLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeNameLookup {
    pub fn new() -> Self {
        Self {
            names: HashMap::new(),
        }
    }

    /// `(token) => string | null`.
    pub fn lookup(
        &mut self,
        bytes: &[u8],
        layout: &ManagedMetadataLayout,
        ranges: &[TypeRange],
        references: &mut ManagedTypeReferences,
        issues: &mut Vec<ManagedParseIssue>,
        token: Option<&str>,
    ) -> ReadResult<Option<String>> {
        let token = match token {
            Some(token) => token,
            None => return Ok(None),
        };
        if let Some(cached) = self.names.get(token) {
            return Ok(cached.clone());
        }
        let table = usize::from_str_radix(&token[2..4], 16).unwrap_or(0);
        let row = i64::from_str_radix(&token[4..], 16).unwrap_or(0);
        // Inline `readManagedValue`: a non-resource reader failure records an
        // issue and yields null; resource-limit and other failures propagate.
        let outcome = if table == 27 {
            self.spec_name(bytes, layout, ranges, references, issues, row)
        } else if table == 1 || table == 2 {
            self.definition_name(bytes, layout, ranges, references, issues, table, row)
        } else {
            Ok(None)
        };
        let name = match outcome {
            Ok(name) => name,
            Err(ReadError::Reader(failure)) => {
                if failure.issue.code == "resource-limit" {
                    return Err(ReadError::Reader(failure));
                }
                issues.push(failure.issue);
                None
            }
            Err(other) => return Err(other),
        };
        self.names.insert(token.to_string(), name.clone());
        Ok(name)
    }

    fn definition_name(
        &mut self,
        bytes: &[u8],
        layout: &ManagedMetadataLayout,
        ranges: &[TypeRange],
        references: &mut ManagedTypeReferences,
        issues: &mut Vec<ManagedParseIssue>,
        table: usize,
        row: i64,
    ) -> ReadResult<Option<String>> {
        if table == 2 {
            metadata_row_offset(layout, 2, row)?;
            return Ok(ranges
                .get((row - 1) as usize)
                .and_then(|range| range.full_name.clone()));
        }
        let reference = references.lookup(bytes, layout, issues, row)?;
        Ok(reference.map(|reference| full_name(&reference.namespace, &reference.name)))
    }

    fn spec_name(
        &mut self,
        bytes: &[u8],
        layout: &ManagedMetadataLayout,
        ranges: &[TypeRange],
        references: &mut ManagedTypeReferences,
        issues: &mut Vec<ManagedParseIssue>,
        row: i64,
    ) -> ReadResult<Option<String>> {
        let mut cursor = metadata_row_cursor(bytes, layout, 27, row)?;
        let spec = read_metadata_blob(
            bytes,
            layout,
            cursor.read_index(layout.blob_index_size)?,
            layout.blob.size,
        )?
        .to_vec();
        let scope = format!("metadata.TypeSpec:{}", metadata_token(27, row));
        spec_signature(layout, &spec, "type", &scope, cursor.start)?;
        if spec.first().copied() != Some(0x15) {
            return Ok(None);
        }
        let encoded = read_compressed(&spec, 2)?.value;
        let table = match encoded & 3 {
            0 => Some(2usize),
            1 => Some(1usize),
            _ => None,
        };
        let table = match table {
            Some(table) => table,
            None => {
                return Err(ReadError::Reader(managed_failure(
                    "invalid-blob",
                    scope,
                    "Generic instantiation does not name a TypeDef or TypeRef",
                    Some(cursor.start as u64),
                )));
            }
        };
        self.definition_name(
            bytes,
            layout,
            ranges,
            references,
            issues,
            table,
            encoded.div_euclid(4),
        )
    }
}
