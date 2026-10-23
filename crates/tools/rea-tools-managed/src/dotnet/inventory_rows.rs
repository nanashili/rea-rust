//! Identity-table row readers: Module, Assembly, AssemblyRef, CustomAttribute,
//! ManifestResource.
//!
//! Port of `src/dotnet/ManagedMetadataInventoryRows.ts`. Each reader returns
//! the exact JSON object the TS producer returns, built in schema key order.

use serde_json::Value;

use super::budget::DigestAlgorithm;
use super::failure::{
    ManagedParseIssue, ManagedReaderFailure, ReadError, managed_failure, read_managed_value,
};
use super::heaps::{
    MetadataRowCursor, budget_digest, metadata_coded_token, metadata_coded_token_invalid_reason,
    metadata_row_cursor, metadata_token, read_metadata_blob, read_metadata_guid,
    read_metadata_string,
};
use super::inventory::ManagedResourceDirectory;
use super::layout::{ManagedMetadataLayout, metadata_row_offset};
use super::member_ownership::{MemberOwnershipCache, member_declaring_type_row_lookup};
use super::type_member_lists::TypeMemberListFacts;

/// `HAS_CUSTOM_ATTRIBUTE_TABLES`.
const HAS_CUSTOM_ATTRIBUTE_TABLES: [Option<usize>; 22] = [
    Some(6),
    Some(4),
    Some(1),
    Some(2),
    Some(8),
    Some(9),
    Some(10),
    Some(0),
    Some(14),
    Some(23),
    Some(20),
    Some(17),
    Some(26),
    Some(27),
    Some(32),
    Some(35),
    Some(38),
    Some(39),
    Some(40),
    Some(42),
    Some(44),
    Some(43),
];

/// `CUSTOM_ATTRIBUTE_TYPE_TABLES`.
const CUSTOM_ATTRIBUTE_TYPE_TABLES: [Option<usize>; 4] = [None, None, Some(6), Some(10)];

/// `0x${value.toString(16)}` body: lowercase hex with no padding or `0x`.
fn hex_lower(value: u32) -> String {
    format!("{value:x}")
}

/// `publicKeyIdentity(bytes, kind, layout)`: a public-key/token projection in
/// schema key order (`kind`, `byte_length`, `sha256`, `token`).
fn public_key_identity(
    data: &[u8],
    source: &[u8],
    kind: &str,
    layout: &ManagedMetadataLayout,
) -> Result<Value, ManagedReaderFailure> {
    let empty = data.is_empty();
    let kind_value = if empty { "none" } else { kind };
    let sha256 = if empty {
        Value::Null
    } else {
        Value::from(budget_digest(
            layout,
            source,
            data,
            DigestAlgorithm::Sha256,
        )?)
    };
    let token = if empty {
        Value::Null
    } else if kind == "public-key" {
        // `Buffer.from(sha1hex, "hex").subarray(-8).reverse().toString("hex")`:
        // last 8 bytes of the SHA-1, reversed, as hex.
        let sha1 = budget_digest(layout, source, data, DigestAlgorithm::Sha1)?;
        let digest = hex_to_bytes(&sha1);
        let start = digest.len().saturating_sub(8);
        let mut tail: Vec<u8> = digest[start..].to_vec();
        tail.reverse();
        Value::from(bytes_to_hex(&tail))
    } else if data.len() == 8 {
        Value::from(bytes_to_hex(data))
    } else {
        Value::Null
    };
    Ok(serde_json::json!({
        "kind": kind_value,
        "byte_length": data.len(),
        "sha256": sha256,
        "token": token,
    }))
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index + 1 < bytes.len() {
        let hi = (bytes[index] as char).to_digit(16).unwrap_or(0);
        let lo = (bytes[index + 1] as char).to_digit(16).unwrap_or(0);
        out.push(((hi << 4) | lo) as u8);
        index += 2;
    }
    out
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `readModule(bytes, layout, heapExtent)`.
pub fn read_module(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    heap_extent: i64,
) -> Result<Option<Value>, ManagedReaderFailure> {
    let table = match layout.table(0) {
        Some(table) if table.row_count != 0 => table.clone(),
        _ => return Ok(None),
    };
    let mut cursor = metadata_row_cursor(bytes, layout, 0, 1)?;
    let generation = cursor.read_u16()?;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        heap_extent,
    )?;
    let mvid = read_metadata_guid(bytes, layout, cursor.read_index(layout.guid_index_size)?)?;
    let enc_id = read_metadata_guid(bytes, layout, cursor.read_index(layout.guid_index_size)?)?;
    let enc_base_id =
        read_metadata_guid(bytes, layout, cursor.read_index(layout.guid_index_size)?)?;
    Ok(Some(serde_json::json!({
        "name": name,
        "generation": generation,
        "mvid": guid_value(mvid),
        "enc_id": guid_value(enc_id),
        "enc_base_id": guid_value(enc_base_id),
        "token": metadata_token(0, 1),
        "row_offset": table.offset,
    })))
}

fn guid_value(guid: Option<String>) -> Value {
    match guid {
        Some(value) => Value::from(value),
        None => Value::Null,
    }
}

/// `readAssembly(bytes, layout, heapExtent)`.
pub fn read_assembly(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    heap_extent: i64,
) -> Result<Option<Value>, ManagedReaderFailure> {
    let table = match layout.table(32) {
        Some(table) if table.row_count != 0 => table.clone(),
        _ => return Ok(None),
    };
    let mut cursor = metadata_row_cursor(bytes, layout, 32, 1)?;
    let hash_algorithm = cursor.read_u32()?;
    let version = format!(
        "{}.{}.{}.{}",
        cursor.read_u16()?,
        cursor.read_u16()?,
        cursor.read_u16()?,
        cursor.read_u16()?
    );
    let flags = cursor.read_u32()?;
    let key = read_metadata_blob(
        bytes,
        layout,
        cursor.read_index(layout.blob_index_size)?,
        heap_extent,
    )?;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        heap_extent,
    )?;
    let culture = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        heap_extent,
    )?;
    let kind = if (flags & 1) == 0 {
        "public-key-token"
    } else {
        "public-key"
    };
    Ok(Some(serde_json::json!({
        "name": name,
        "version": version,
        "culture": if culture.is_empty() { Value::Null } else { Value::from(culture) },
        "flags": flags,
        "hash_algorithm": hash_algorithm,
        "public_key": public_key_identity(&key, bytes, kind, layout)?,
        "token": metadata_token(32, 1),
        "row_offset": table.offset,
    })))
}

/// Shared AssemblyRef prefix: version, flags, and the key/name heap indexes.
struct AssemblyReferenceHeader<'a> {
    cursor: MetadataRowCursor<'a>,
    version: String,
    flags: u32,
    key_index: u32,
    name_index: u32,
}

fn assembly_reference_header<'a>(
    bytes: &'a [u8],
    layout: &ManagedMetadataLayout,
    row: i64,
) -> Result<AssemblyReferenceHeader<'a>, ManagedReaderFailure> {
    let mut cursor = metadata_row_cursor(bytes, layout, 35, row)?;
    let version = format!(
        "{}.{}.{}.{}",
        cursor.read_u16()?,
        cursor.read_u16()?,
        cursor.read_u16()?,
        cursor.read_u16()?
    );
    let flags = cursor.read_u32()?;
    let key_index = cursor.read_index(layout.blob_index_size)?;
    let name_index = cursor.read_index(layout.string_index_size)?;
    Ok(AssemblyReferenceHeader {
        cursor,
        version,
        flags,
        key_index,
        name_index,
    })
}

/// `readAssemblyReference(bytes, layout, row, heapExtent)`.
pub fn read_assembly_reference(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    row: i64,
    heap_extent: i64,
) -> Result<Value, ManagedReaderFailure> {
    let AssemblyReferenceHeader {
        mut cursor,
        version,
        flags,
        key_index,
        name_index,
    } = assembly_reference_header(bytes, layout, row)?;
    let key_or_token = read_metadata_blob(bytes, layout, key_index, heap_extent)?;
    let name = read_metadata_string(bytes, layout, name_index, heap_extent)?;
    let culture = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        heap_extent,
    )?;
    let hash_value = read_metadata_blob(
        bytes,
        layout,
        cursor.read_index(layout.blob_index_size)?,
        heap_extent,
    )?;
    let kind = if (flags & 1) == 0 {
        "public-key-token"
    } else {
        "public-key"
    };
    let hash_value_sha256 = if hash_value.is_empty() {
        Value::Null
    } else {
        Value::from(budget_digest(
            layout,
            bytes,
            &hash_value,
            DigestAlgorithm::Sha256,
        )?)
    };
    Ok(serde_json::json!({
        "name": name,
        "version": version,
        "culture": if culture.is_empty() { Value::Null } else { Value::from(culture) },
        "flags": flags,
        "public_key_or_token": public_key_identity(&key_or_token, bytes, kind, layout)?,
        "hash_value_sha256": hash_value_sha256,
        "hash_value_length": hash_value.len(),
        "token": metadata_token(35, row),
        "row_offset": metadata_row_offset(layout, 35, row)?,
    }))
}

/// `readTypeName({ bytes, layout, table, row, heapExtent })`: a
/// namespace-qualified name for a TypeDef (2) or TypeRef (1) row, or `None`.
fn read_type_name(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    table: usize,
    row: i64,
    heap_extent: i64,
) -> Result<Option<String>, ManagedReaderFailure> {
    match layout.table(table) {
        Some(descriptor) if row >= 1 && row <= descriptor.row_count => {}
        _ => return Ok(None),
    }
    let mut cursor = metadata_row_cursor(bytes, layout, table, row)?;
    if table == 1 {
        cursor.read_index(layout.coded_index_size("ResolutionScope"))?;
    } else {
        cursor.read_u32()?;
    }
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        heap_extent,
    )?;
    let namespace = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        heap_extent,
    )?;
    Ok(Some(if namespace.is_empty() {
        name
    } else {
        format!("{namespace}.{name}")
    }))
}

fn declaring_type_for_method(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    method_row: i64,
    heap_extent: i64,
    member_lists: &TypeMemberListFacts,
    ownership: &MemberOwnershipCache,
) -> Result<Option<String>, ManagedReaderFailure> {
    let lookup = member_declaring_type_row_lookup(ownership, bytes, layout, 6, member_lists)?;
    let owner = lookup.lookup(ownership, method_row)?;
    if owner == 0 {
        return Ok(None);
    }
    read_type_name(bytes, layout, 2, owner, heap_extent)
}

fn attribute_type_name(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    raw_type: u32,
    heap_extent: i64,
    member_lists: &TypeMemberListFacts,
    ownership: &MemberOwnershipCache,
) -> Result<Option<String>, ManagedReaderFailure> {
    let tag = raw_type & 7;
    let row = (raw_type / 8) as i64;
    if row == 0 {
        return Ok(None);
    }
    if tag == 2 {
        return declaring_type_for_method(bytes, layout, row, heap_extent, member_lists, ownership);
    }
    if tag != 3 {
        return Ok(None);
    }
    match layout.table(10) {
        Some(table) if row <= table.row_count => {}
        _ => return Ok(None),
    }
    let mut cursor = metadata_row_cursor(bytes, layout, 10, row)?;
    let parent = cursor.read_index(layout.coded_index_size("MemberRefParent"))?;
    let parent_tag = parent & 7;
    let parent_row = (parent / 8) as i64;
    if parent_tag == 0 {
        return read_type_name(bytes, layout, 2, parent_row, heap_extent);
    }
    if parent_tag == 1 {
        return read_type_name(bytes, layout, 1, parent_row, heap_extent);
    }
    if parent_tag == 3 {
        return declaring_type_for_method(
            bytes,
            layout,
            parent_row,
            heap_extent,
            member_lists,
            ownership,
        );
    }
    Ok(None)
}

/// `decodeCompressedLength(blob, offset)`: ECMA-335 compressed unsigned length.
fn decode_compressed_length(blob: &[u8], offset: usize) -> Option<(i64, usize)> {
    let first = *blob.get(offset)? as i64;
    if (first & 0x80) == 0 {
        return Some((first, 1));
    }
    if (first & 0xc0) == 0x80 && blob.get(offset + 1).is_some() {
        let length = ((first & 0x3f) << 8) | (*blob.get(offset + 1).unwrap_or(&0) as i64);
        return Some((length, 2));
    }
    if (first & 0xe0) == 0xc0
        && blob.get(offset + 1).is_some()
        && blob.get(offset + 2).is_some()
        && blob.get(offset + 3).is_some()
    {
        let length = (first & 0x1f) * 0x01_00_00_00
            + (*blob.get(offset + 1).unwrap_or(&0) as i64) * 0x01_00_00
            + (*blob.get(offset + 2).unwrap_or(&0) as i64) * 0x0100
            + (*blob.get(offset + 3).unwrap_or(&0) as i64);
        return Some((length, 4));
    }
    None
}

/// `decodeFixedString(blob, layout)`: a CustomAttribute fixed-string argument.
fn decode_fixed_string(
    blob: &[u8],
    layout: &ManagedMetadataLayout,
) -> Result<Option<String>, ManagedReaderFailure> {
    if blob.len() < 3
        || u16::from_le_bytes([blob[0], blob[1]]) != 1
        || blob.get(2).copied() == Some(0xff)
    {
        return Ok(None);
    }
    let (length, prefix) = match decode_compressed_length(blob, 2) {
        Some(value) => value,
        None => return Ok(None),
    };
    let start = 2 + prefix as i64;
    if start > blob.len() as i64 - length {
        return Ok(None);
    }
    layout
        .budget()
        .reserve_string(length, Some(layout.blob.offset as u64))?;
    let slice = &blob[start as usize..(start + length) as usize];
    // `TextDecoder("utf-8", { fatal: true })`: invalid UTF-8 decodes as null.
    match std::str::from_utf8(slice) {
        Ok(value) => Ok(Some(value.to_string())),
        Err(_) => Ok(None),
    }
}

/// `readCustomAttribute(bytes, layout, row, heapExtent, issues, memberLists)`.
///
/// The TS WeakMap-caches the owner lookup per facts; the caller passes a shared
/// [`MemberOwnershipCache`] for the whole attribute pass to reproduce that.
#[allow(clippy::too_many_arguments)]
pub fn read_custom_attribute(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    row: i64,
    heap_extent: i64,
    issues: &mut Vec<ManagedParseIssue>,
    member_lists: &TypeMemberListFacts,
    ownership: &MemberOwnershipCache,
) -> Result<Value, ManagedReaderFailure> {
    let mut cursor = metadata_row_cursor(bytes, layout, 12, row)?;
    let cursor_start = cursor.start;
    let parent_raw = cursor.read_index(layout.coded_index_size("HasCustomAttribute"))?;
    let type_offset = cursor.offset();
    let type_raw = cursor.read_index(layout.coded_index_size("CustomAttributeType"))?;
    let value = read_metadata_blob(
        bytes,
        layout,
        cursor.read_index(layout.blob_index_size)?,
        heap_extent,
    )?;
    let parent = metadata_coded_token(
        parent_raw,
        5,
        &HAS_CUSTOM_ATTRIBUTE_TABLES,
        &layout.row_counts,
    );
    let parent = match parent {
        Some(parent) => parent,
        None => {
            let reason = metadata_coded_token_invalid_reason(
                parent_raw,
                5,
                &HAS_CUSTOM_ATTRIBUTE_TABLES,
                &layout.row_counts,
            );
            return Err(managed_failure(
                "invalid-row",
                format!("metadata.CustomAttribute:{}", metadata_token(12, row)),
                format!(
                    "CustomAttribute parent coded index 0x{} is invalid{}",
                    hex_lower(parent_raw),
                    match reason {
                        None => " because the required parent is null".to_string(),
                        Some(reason) => format!(": {reason}"),
                    }
                ),
                Some(cursor_start as u64),
            ));
        }
    };
    let constructor = metadata_coded_token(
        type_raw,
        3,
        &CUSTOM_ATTRIBUTE_TYPE_TABLES,
        &layout.row_counts,
    );
    if constructor.is_none() {
        let type_reason = metadata_coded_token_invalid_reason(
            type_raw,
            3,
            &CUSTOM_ATTRIBUTE_TYPE_TABLES,
            &layout.row_counts,
        );
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: format!("metadata.CustomAttribute:{}", metadata_token(12, row)),
            offset: Some(type_offset as u64),
            detail: match type_reason {
                None => "CustomAttribute constructor coded index 0x0 is null, but Type must reference a MethodDef or MemberRef row".to_string(),
                Some(reason) => format!(
                    "CustomAttribute constructor coded index 0x{} is invalid: {reason}",
                    hex_lower(type_raw)
                ),
            },
        });
    }
    let mut type_name: Option<String> = None;
    if constructor.is_some() {
        type_name = read_managed_value(
            || {
                attribute_type_name(
                    bytes,
                    layout,
                    type_raw,
                    heap_extent,
                    member_lists,
                    ownership,
                )
                .map_err(ReadError::from)
            },
            issues,
        )
        .map_err(reader_error)?
        .flatten();
    }
    let decoded_fixed_string =
        if type_name.as_deref() == Some("System.Runtime.Versioning.TargetFrameworkAttribute") {
            decode_fixed_string(&value, layout)?
        } else {
            None
        };
    Ok(serde_json::json!({
        "parent_token": parent,
        "constructor_token": option_value(constructor),
        "type_name": option_value(type_name),
        "value_length": value.len(),
        "value_sha256": budget_digest(layout, bytes, &value, DigestAlgorithm::Sha256)?,
        "decoded_fixed_string": option_value(decoded_fixed_string),
        "token": metadata_token(12, row),
        "row_offset": cursor_start,
    }))
}

fn option_value(value: Option<String>) -> Value {
    match value {
        Some(value) => Value::from(value),
        None => Value::Null,
    }
}

/// Convert a `ReadError` raised by `read_managed_value` back into a
/// `ManagedReaderFailure`. Only a `resource-limit` reader failure propagates
/// from `attribute_type_name`; internal failures map with a kept message.
fn reader_error(error: ReadError) -> ManagedReaderFailure {
    match error {
        ReadError::Reader(failure) => failure,
        ReadError::Internal(internal) => {
            managed_failure("invalid-row", "metadata.CustomAttribute", internal.0, None)
        }
    }
}

/// `ResourceContext`: inputs for `readResource`.
pub struct ResourceContext<'a, 'i> {
    pub bytes: &'a [u8],
    pub layout: &'a ManagedMetadataLayout,
    pub row: i64,
    pub directory: Option<ManagedResourceDirectory>,
    pub issues: &'i mut Vec<ManagedParseIssue>,
}

/// `readResource({ bytes, layout, row, directory, issues })`.
pub fn read_resource(context: ResourceContext<'_, '_>) -> Result<Value, ManagedReaderFailure> {
    let ResourceContext {
        bytes,
        layout,
        row,
        directory,
        issues,
    } = context;
    let mut cursor = metadata_row_cursor(bytes, layout, 40, row)?;
    let cursor_start = cursor.start;
    let declared_offset = cursor.read_u32()?;
    let flags = cursor.read_u32()?;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size.max(layout.blob.size),
    )?;
    let implementation_offset = cursor.offset();
    let implementation_raw = cursor.read_index(layout.coded_index_size("Implementation"))?;
    let implementation_token = metadata_coded_token(
        implementation_raw,
        2,
        &[Some(38), Some(35), Some(39)],
        &layout.row_counts,
    );
    let implementation_reason = metadata_coded_token_invalid_reason(
        implementation_raw,
        2,
        &[Some(38), Some(35), Some(39)],
        &layout.row_counts,
    );
    if let Some(reason) = implementation_reason {
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: format!("metadata.ManifestResource:{}", metadata_token(40, row)),
            offset: Some(implementation_offset as u64),
            detail: format!(
                "ManifestResource implementation coded index 0x{} is invalid: {reason}",
                hex_lower(implementation_raw)
            ),
        });
    }
    let mut data_length: Option<i64> = None;
    let mut data_sha256: Option<String> = None;
    if implementation_raw == 0 {
        match directory {
            None => {
                issues.push(embedded_offset_issue(row, None));
            }
            Some(dir) if declared_offset as i64 > dir.size - 4 => {
                issues.push(embedded_offset_issue(row, Some(dir.offset as u64)));
            }
            Some(dir) => {
                let start = dir.offset + declared_offset as i64;
                let length = super::bytes::read_u32(bytes, start as usize)
                    .map_err(|_| resource_internal(row))? as i64;
                data_length = Some(length);
                if length > dir.size - declared_offset as i64 - 4 {
                    issues.push(ManagedParseIssue {
                        code: "invalid-resource",
                        scope: format!("metadata.ManifestResource:{}", metadata_token(40, row)),
                        offset: Some(start as u64),
                        detail: "Embedded resource length leaves the CLI resources directory"
                            .to_string(),
                    });
                } else {
                    let slice = &bytes[(start + 4) as usize..(start + 4 + length) as usize];
                    data_sha256 = Some(budget_digest(
                        layout,
                        bytes,
                        slice,
                        DigestAlgorithm::Sha256,
                    )?);
                }
            }
        }
    }
    Ok(serde_json::json!({
        "name": name,
        "flags": flags,
        "visibility": match flags & 7 {
            1 => "public",
            2 => "private",
            _ => "unknown",
        },
        "implementation_token": option_value(implementation_token),
        "embedded": implementation_raw == 0,
        "declared_offset": declared_offset,
        "data_length": match data_length {
            Some(length) => Value::from(length),
            None => Value::Null,
        },
        "data_sha256": option_value(data_sha256),
        "token": metadata_token(40, row),
        "row_offset": cursor_start,
    }))
}

fn embedded_offset_issue(row: i64, offset: Option<u64>) -> ManagedParseIssue {
    ManagedParseIssue {
        code: "invalid-resource",
        scope: format!("metadata.ManifestResource:{}", metadata_token(40, row)),
        offset,
        detail: "Embedded resource offset leaves the CLI resources directory".to_string(),
    }
}

fn resource_internal(row: i64) -> ManagedReaderFailure {
    managed_failure(
        "invalid-resource",
        format!("metadata.ManifestResource:{}", metadata_token(40, row)),
        "Embedded resource read left the artifact byte range",
        None,
    )
}
