//! Field, ExportedType, MemberRef, and MethodDef row projections and edges.
//!
//! Port of `src/dotnet/ManagedMemberRows.ts`. Declaring-type selection decodes
//! members of selected types in full; unselected members keep only their name
//! so edges stay labelled. Each signature blob is decoded under the shared
//! representation budget.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use super::budget::{DigestAlgorithm, admit_managed_projection};
use super::failure::{ManagedParseIssue, ReadError, ReadResult, read_managed_value};
use super::heaps::{
    metadata_coded_token, metadata_coded_token_invalid_reason, metadata_row_cursor, metadata_token,
    read_metadata_blob, read_metadata_string,
};
use super::layout::ManagedMetadataLayout;
use super::member_core::{MemberCore, SignatureTypeName, TypeRange, signature_with_facts};
use super::member_ownership::{
    MemberOwnershipCache, OwnerLookup, member_declaring_type_row_lookup,
};
use super::method_body::{Anchor, method_body};
use super::pe_reader::ManagedPeLayout;
use super::type_member_lists::TypeMemberListFacts;
use crate::common::json::json_string_byte_length;

/// Declaring-type tokens whose members are decoded in full; `None` selects
/// every type.
pub type SelectedTypeTokens<'a> = Option<&'a HashSet<String>>;

fn is_selected(selected: SelectedTypeTokens<'_>, declared: Option<&TypeRange>) -> bool {
    match selected {
        None => true,
        Some(selected) => declared
            .map(|range| selected.contains(&range.token))
            .unwrap_or(false),
    }
}

/// `budgetedSignature(bytes, layout, signatureTypeName)`: decode one signature
/// blob under a transient allocation, returning its projection value and the
/// decoded kind and generic arity.
fn budgeted_signature(
    blob: &[u8],
    blob_range_key: Option<&str>,
    layout: &ManagedMetadataLayout,
    signature_type_name: &mut SignatureTypeName<'_>,
) -> ReadResult<(Value, &'static str, Option<i64>)> {
    layout
        .budget()
        .admit_transient(blob.len() as i64 * 256, Some(layout.blob.offset as u64))?;
    let outcome = (|| -> ReadResult<(Value, &'static str, Option<i64>)> {
        let raw = layout
            .budget()
            .digest(blob, blob_range_key, DigestAlgorithm::Sha256)?;
        let (value, kind, arity) = signature_with_facts(blob, Some(raw), signature_type_name);
        admit_managed_projection(&value, Some(&mut layout.budget()))?;
        Ok((value, kind, arity))
    })();
    layout.budget().release_transient();
    outcome
}

/// The budget digest cache identity of a #Blob read (`heaps::range_key`):
/// equal artifact ranges reuse one reservation, and a null-index blob (its
/// own empty buffer in TS) is never cached.
fn blob_range_key(bytes: &[u8], blob: &[u8]) -> Option<String> {
    super::heaps::range_key(bytes, blob)
}

/// Output of `parseFields`.
pub struct ParsedFields {
    pub fields: Vec<Value>,
    pub core: HashMap<String, MemberCore>,
    pub issues: Vec<ManagedParseIssue>,
}

/// `parseFields(bytes, layout, ranges, memberLists, {signatureTypeName, selected})`.
pub fn parse_fields(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    ranges: &[TypeRange],
    member_lists: &TypeMemberListFacts,
    signature_type_name: &mut SignatureTypeName<'_>,
    selected: SelectedTypeTokens<'_>,
) -> ReadResult<ParsedFields> {
    let mut fields: Vec<Value> = Vec::new();
    let mut core: HashMap<String, MemberCore> = HashMap::new();
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let table_rows = layout.table(4).map(|t| t.row_count).unwrap_or(0);
    let cache = MemberOwnershipCache::default();
    let owner_row = read_managed_value(
        || {
            member_declaring_type_row_lookup(&cache, bytes, layout, 4, member_lists)
                .map_err(ReadError::from)
        },
        &mut issues,
    )?;
    for row in 1..=table_rows {
        // Resolve the owner outside the fallible read, as the TS does.
        let owner = resolve_owner(owner_row.as_ref(), &cache, row, &mut issues)?.unwrap_or(0);
        let declared = ranges.get((owner - 1) as usize);
        let outcome = parse_field_row(
            bytes,
            layout,
            declared,
            signature_type_name,
            selected,
            &mut core,
            &mut fields,
            row,
        );
        propagate(outcome, &mut issues)?;
    }
    Ok(ParsedFields {
        fields,
        core,
        issues,
    })
}

/// Resolve an owner row through `readManagedValue`, yielding `None` when the
/// lookup is absent (TS `undefined`) or recorded a failure.
fn resolve_owner(
    owner_row: Option<&OwnerLookup>,
    cache: &MemberOwnershipCache,
    row: i64,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<Option<i64>> {
    match owner_row {
        None => Ok(None),
        Some(lookup) => read_managed_value(
            || lookup.lookup(cache, row).map_err(ReadError::from),
            issues,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_field_row(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    declared: Option<&TypeRange>,
    signature_type_name: &mut SignatureTypeName<'_>,
    selected: SelectedTypeTokens<'_>,
    core: &mut HashMap<String, MemberCore>,
    fields: &mut Vec<Value>,
    row: i64,
) -> ReadResult<()> {
    let mut cursor = metadata_row_cursor(bytes, layout, 4, row)?;
    let flags = cursor.read_u16()? as i64;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size,
    )?;
    let token = metadata_token(4, row);
    core.insert(
        token.clone(),
        MemberCore {
            token: token.clone(),
            name: name.clone(),
            declaring_type: declared.and_then(|range| range.full_name.clone()),
            kind: "field",
            generic_arity: None,
        },
    );
    if !is_selected(selected, declared) {
        return Ok(());
    }
    let blob = read_metadata_blob(
        bytes,
        layout,
        cursor.read_index(layout.blob_index_size)?,
        layout.blob.size,
    )?;
    let key = blob_range_key(bytes, blob);
    let blob_owned = blob.to_vec();
    let (signature, _kind, _arity) =
        budgeted_signature(&blob_owned, key.as_deref(), layout, signature_type_name)?;
    let mut map = Map::new();
    map.insert("token".into(), Value::from(token));
    map.insert("row_offset".into(), Value::from(cursor.start));
    map.insert(
        "declaring_type_token".into(),
        declared
            .map(|range| Value::from(range.token.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "declaring_type".into(),
        declared
            .and_then(|range| range.full_name.clone())
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    map.insert("name".into(), Value::from(name));
    map.insert("flags".into(), Value::from(flags));
    map.insert("signature".into(), signature);
    fields.push(Value::Object(map));
    Ok(())
}

const TYPE_FORWARDER_FLAG: i64 = 0x0020_0000;

/// Output of `parseExportedTypes`.
pub struct ParsedExportedTypes {
    pub exported_types: Vec<Value>,
    pub issues: Vec<ManagedParseIssue>,
}

/// `parseExportedTypes(bytes, layout)`.
pub fn parse_exported_types(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
) -> ReadResult<ParsedExportedTypes> {
    let mut exported_types: Vec<Value> = Vec::new();
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let table_rows = layout.table(39).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=table_rows {
        let outcome = parse_exported_type_row(bytes, layout, &mut exported_types, &mut issues, row);
        propagate(outcome, &mut issues)?;
    }
    Ok(ParsedExportedTypes {
        exported_types,
        issues,
    })
}

fn parse_exported_type_row(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    exported_types: &mut Vec<Value>,
    issues: &mut Vec<ManagedParseIssue>,
    row: i64,
) -> ReadResult<()> {
    let mut cursor = metadata_row_cursor(bytes, layout, 39, row)?;
    let flags = cursor.read_u32()? as i64;
    let type_def_id = cursor.read_u32()? as i64;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size,
    )?;
    let namespace = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size,
    )?;
    let implementation_offset = cursor.offset();
    let implementation_raw = cursor.read_index(layout.coded_index_size("Implementation"))?;
    let token = metadata_token(39, row);
    let tables = [Some(38usize), Some(35), Some(39)];
    let implementation_reason =
        metadata_coded_token_invalid_reason(implementation_raw, 2, &tables, &layout.row_counts);
    if implementation_reason.is_some() || implementation_raw == 0 {
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: format!("metadata.ExportedType:{token}"),
            offset: Some(implementation_offset as u64),
            detail: match &implementation_reason {
                None => "ExportedType implementation coded index 0x0 is null, but the Implementation column must reference a row".to_string(),
                Some(reason) => format!(
                    "ExportedType implementation coded index 0x{implementation_raw:x} is invalid: {reason}"
                ),
            },
        });
    }
    let mut map = Map::new();
    map.insert("token".into(), Value::from(token));
    map.insert("row_offset".into(), Value::from(cursor.start));
    map.insert("namespace".into(), Value::from(namespace));
    map.insert("name".into(), Value::from(name));
    map.insert("flags".into(), Value::from(flags));
    map.insert(
        "forwarder".into(),
        Value::from((flags & TYPE_FORWARDER_FLAG) != 0),
    );
    map.insert("type_def_id".into(), Value::from(type_def_id));
    map.insert(
        "implementation_token".into(),
        metadata_coded_token(implementation_raw, 2, &tables, &layout.row_counts)
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    exported_types.push(Value::Object(map));
    Ok(())
}

/// Output of `parseMemberRefs`.
pub struct ParsedMemberRefs {
    pub refs: Vec<Value>,
    pub core: HashMap<String, MemberCore>,
    pub issues: Vec<ManagedParseIssue>,
}

/// `parseMemberRefs(bytes, layout, typeName, signatureTypeName)`.
///
/// `type_name` resolves a parent token to a declaring-type name; it borrows the
/// same shared issue accumulator through its own capture, as in the TS.
pub fn parse_member_refs(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    type_name: &mut dyn FnMut(Option<&str>) -> ReadResult<Option<String>>,
    signature_type_name: &mut SignatureTypeName<'_>,
) -> ReadResult<ParsedMemberRefs> {
    let mut refs: Vec<Value> = Vec::new();
    let mut core: HashMap<String, MemberCore> = HashMap::new();
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let table_rows = layout.table(10).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=table_rows {
        let outcome = parse_member_ref_row(
            bytes,
            layout,
            type_name,
            signature_type_name,
            &mut core,
            &mut refs,
            &mut issues,
            row,
        );
        propagate(outcome, &mut issues)?;
    }
    Ok(ParsedMemberRefs { refs, core, issues })
}

#[allow(clippy::too_many_arguments)]
fn parse_member_ref_row(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    type_name: &mut dyn FnMut(Option<&str>) -> ReadResult<Option<String>>,
    signature_type_name: &mut SignatureTypeName<'_>,
    core: &mut HashMap<String, MemberCore>,
    refs: &mut Vec<Value>,
    issues: &mut Vec<ManagedParseIssue>,
    row: i64,
) -> ReadResult<()> {
    let mut cursor = metadata_row_cursor(bytes, layout, 10, row)?;
    let parent_raw = cursor.read_index(layout.coded_index_size("MemberRefParent"))?;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size,
    )?;
    let blob = read_metadata_blob(
        bytes,
        layout,
        cursor.read_index(layout.blob_index_size)?,
        layout.blob.size,
    )?;
    let key = blob_range_key(bytes, blob);
    let blob_owned = blob.to_vec();
    let token = metadata_token(10, row);
    let tables = [Some(2usize), Some(1), Some(26), Some(6), Some(27)];
    let parent_reason =
        metadata_coded_token_invalid_reason(parent_raw, 3, &tables, &layout.row_counts);
    if parent_reason.is_some() || parent_raw == 0 {
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: format!("metadata.MemberRef:{token}"),
            offset: Some(cursor.start as u64),
            detail: match &parent_reason {
                None => "MemberRef parent coded index 0x0 is null, but the Class column must reference a row".to_string(),
                Some(reason) => format!(
                    "MemberRef parent coded index 0x{parent_raw:x} is invalid: {reason}"
                ),
            },
        });
    }
    let parent_token = metadata_coded_token(parent_raw, 3, &tables, &layout.row_counts);
    let parent_name = type_name(parent_token.as_deref())?;
    let (signature, kind, arity) =
        budgeted_signature(&blob_owned, key.as_deref(), layout, signature_type_name)?;
    let mut map = Map::new();
    map.insert("token".into(), Value::from(token.clone()));
    map.insert("row_offset".into(), Value::from(cursor.start));
    map.insert(
        "parent_token".into(),
        parent_token.map(Value::from).unwrap_or(Value::Null),
    );
    map.insert(
        "parent_name".into(),
        parent_name.clone().map(Value::from).unwrap_or(Value::Null),
    );
    map.insert("name".into(), Value::from(name.clone()));
    map.insert("signature".into(), signature);
    refs.push(Value::Object(map));
    core.insert(
        token.clone(),
        MemberCore {
            token,
            name,
            declaring_type: parent_name,
            kind,
            generic_arity: Some(arity),
        },
    );
    Ok(())
}

/// Output of `parseMethods`.
pub struct ParsedMethods {
    pub methods: Vec<Value>,
    pub method_anchors: Vec<Vec<Anchor>>,
    pub method_statuses: Vec<&'static str>,
    pub core: HashMap<String, MemberCore>,
    pub issues: Vec<ManagedParseIssue>,
    pub unscanned_methods: i64,
}

/// `parseMethods({...})`.
#[allow(clippy::too_many_arguments)]
pub fn parse_methods(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    pe: &ManagedPeLayout,
    ranges: &[TypeRange],
    signature_type_name: &mut SignatureTypeName<'_>,
    member_lists: &TypeMemberListFacts,
    selected: SelectedTypeTokens<'_>,
    method_offset: i64,
    method_limit: i64,
) -> ReadResult<ParsedMethods> {
    let mut methods: Vec<Value> = Vec::new();
    let mut method_anchors: Vec<Vec<Anchor>> = Vec::new();
    let mut method_statuses: Vec<&'static str> = Vec::new();
    let mut core: HashMap<String, MemberCore> = HashMap::new();
    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let mut unscanned_methods: i64 = 0;
    let table_rows = layout.table(6).map(|t| t.row_count).unwrap_or(0);
    let cache = MemberOwnershipCache::default();
    let owner_row = read_managed_value(
        || {
            member_declaring_type_row_lookup(&cache, bytes, layout, 6, member_lists)
                .map_err(ReadError::from)
        },
        &mut issues,
    )?;
    for row in 1..=table_rows {
        // The owner is read first: a row that produced no method hides a
        // selected body only when its owner is selected, unknown, or
        // unreadably named.
        let owner = resolve_owner(owner_row.as_ref(), &cache, row, &mut issues)?;
        let declared = owner.and_then(|owner| ranges.get((owner - 1) as usize));
        let in_page = row > method_offset && row - method_offset <= method_limit;
        let may_be_selected = in_page
            && (selected.is_none()
                || owner.is_none()
                || is_selected(selected, declared)
                // A type whose name is unreadable may be one the caller requested.
                || declared.map(|range| range.full_name.is_none()).unwrap_or(false));
        let produced = methods.len();
        let outcome = parse_method_row(
            bytes,
            layout,
            pe,
            declared,
            signature_type_name,
            selected,
            in_page,
            &mut core,
            &mut methods,
            &mut method_anchors,
            &mut method_statuses,
            &mut unscanned_methods,
            row,
        );
        propagate(outcome, &mut issues)?;
        if may_be_selected && methods.len() == produced {
            unscanned_methods += 1;
        }
    }
    Ok(ParsedMethods {
        methods,
        method_anchors,
        method_statuses,
        core,
        issues,
        unscanned_methods,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_method_row(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    pe: &ManagedPeLayout,
    declared: Option<&TypeRange>,
    signature_type_name: &mut SignatureTypeName<'_>,
    selected: SelectedTypeTokens<'_>,
    in_page: bool,
    core: &mut HashMap<String, MemberCore>,
    methods: &mut Vec<Value>,
    method_anchors: &mut Vec<Vec<Anchor>>,
    method_statuses: &mut Vec<&'static str>,
    unscanned_methods: &mut i64,
    row: i64,
) -> ReadResult<()> {
    let mut cursor = metadata_row_cursor(bytes, layout, 6, row)?;
    let rva = cursor.read_u32()? as i64;
    let impl_flags = cursor.read_u16()? as i64;
    let flags = cursor.read_u16()? as i64;
    let name = read_metadata_string(
        bytes,
        layout,
        cursor.read_index(layout.string_index_size)?,
        layout.strings.size,
    )?;
    let token = metadata_token(6, row);
    core.insert(
        token.clone(),
        MemberCore {
            token: token.clone(),
            name: name.clone(),
            declaring_type: declared.and_then(|range| range.full_name.clone()),
            kind: "method",
            generic_arity: None,
        },
    );
    if !in_page {
        return Ok(());
    }
    if !is_selected(selected, declared) {
        return Ok(());
    }
    let blob = read_metadata_blob(
        bytes,
        layout,
        cursor.read_index(layout.blob_index_size)?,
        layout.blob.size,
    )?;
    let key = blob_range_key(bytes, blob);
    let blob_owned = blob.to_vec();
    cursor.read_index(layout.table_index_size(8))?;
    let (signature, _kind, arity) =
        budgeted_signature(&blob_owned, key.as_deref(), layout, signature_type_name)?;
    core.insert(
        token.clone(),
        MemberCore {
            token: token.clone(),
            name: name.clone(),
            declaring_type: declared.and_then(|range| range.full_name.clone()),
            kind: "method",
            generic_arity: Some(arity),
        },
    );
    let read = method_body(bytes, pe, layout, rva, impl_flags, flags)?;
    if !read.scanned {
        *unscanned_methods += 1;
    }
    let mut map = Map::new();
    map.insert("token".into(), Value::from(token));
    map.insert("row_offset".into(), Value::from(cursor.start));
    map.insert(
        "declaring_type_token".into(),
        declared
            .map(|range| Value::from(range.token.clone()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "declaring_type".into(),
        declared
            .and_then(|range| range.full_name.clone())
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    map.insert("name".into(), Value::from(name));
    map.insert("rva".into(), Value::from(rva));
    map.insert("impl_flags".into(), Value::from(impl_flags));
    map.insert("flags".into(), Value::from(flags));
    map.insert("signature".into(), signature);
    map.insert("body".into(), read.body.value);
    methods.push(Value::Object(map));
    method_anchors.push(read.body.anchors);
    method_statuses.push(read.body.status);
    Ok(())
}

/// Replicate `readManagedValue` at the row level: a non-resource reader failure
/// records an issue and continues; resource-limit and other failures propagate.
fn propagate(outcome: ReadResult<()>, issues: &mut Vec<ManagedParseIssue>) -> ReadResult<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(ReadError::Reader(failure)) => {
            if failure.issue.code == "resource-limit" {
                Err(ReadError::Reader(failure))
            } else {
                issues.push(failure.issue);
                Ok(())
            }
        }
        Err(other) => Err(other),
    }
}

// ---- Edges ----------------------------------------------------------------

/// Whether an operand kind may name a member of `member_kind`.
fn nameable(operand_kind: &str, member_kind: &str) -> bool {
    match operand_kind {
        "method" => member_kind == "method" || member_kind == "unknown",
        "field" => member_kind == "field",
        _ => false,
    }
}

fn target_kind(token: &str) -> &'static str {
    if token.starts_with("0x06") {
        "method-def"
    } else if token.starts_with("0x0a") {
        "member-ref"
    } else if token.starts_with("0x2b") {
        "method-spec"
    } else {
        "unknown"
    }
}

/// Output of `edges`: call edges and field accesses, both in schema key order.
pub struct Edges {
    pub call_edges: Vec<Value>,
    pub field_accesses: Vec<Value>,
}

/// A decoded method available to `edges`.
pub struct EdgeMethod<'a> {
    pub token: &'a str,
    pub name: &'a str,
    pub declaring_type: Option<&'a str>,
    pub anchors: &'a [Anchor],
}

/// `edges(methods, members, budget)`.
pub fn edges(
    methods: &[EdgeMethod<'_>],
    members: &HashMap<String, MemberCore>,
    layout: &ManagedMetadataLayout,
) -> ReadResult<Edges> {
    let mut call_edges: Vec<Value> = Vec::new();
    let mut field_accesses: Vec<Value> = Vec::new();
    for method in methods {
        let derives = method.anchors.iter().any(|anchor| {
            anchor.opcode != "ldtoken"
                && anchor.operand.is_some()
                && (anchor.operand_kind == "method" || anchor.operand_kind == "field")
        });
        if derives {
            layout
                .budget()
                .admit_transient(caller_name_bytes(method), None)?;
        }
        // Built once per method, only after its exact size was admitted.
        let caller = if derives {
            caller_name(method)
        } else {
            method.name.to_string()
        };
        for anchor in method.anchors {
            if anchor.opcode == "ldtoken" {
                continue;
            }
            let operand = match &anchor.operand {
                Some(operand) => operand,
                None => continue,
            };
            let target = named_target(members, anchor.operand_kind, operand);
            if anchor.operand_kind == "method" {
                let mut map = Map::new();
                map.insert("caller_token".into(), Value::from(method.token.to_string()));
                map.insert("caller".into(), Value::from(caller.clone()));
                map.insert("opcode".into(), Value::from(anchor.opcode));
                map.insert("target_token".into(), Value::from(operand.clone()));
                map.insert("target_kind".into(), Value::from(target_kind(operand)));
                map.insert(
                    "target_name".into(),
                    target
                        .map(|member| Value::from(member.name.clone()))
                        .unwrap_or(Value::Null),
                );
                map.insert(
                    "target_declaring_type".into(),
                    target
                        .and_then(|member| member.declaring_type.clone())
                        .map(Value::from)
                        .unwrap_or(Value::Null),
                );
                let edge = Value::Object(map);
                admit_managed_projection(&edge, Some(&mut layout.budget()))?;
                call_edges.push(edge);
            }
            if anchor.operand_kind == "field" {
                let mut map = Map::new();
                map.insert("method_token".into(), Value::from(method.token.to_string()));
                map.insert("method".into(), Value::from(caller.clone()));
                map.insert("opcode".into(), Value::from(anchor.opcode));
                map.insert("field_token".into(), Value::from(operand.clone()));
                map.insert(
                    "field_name".into(),
                    target
                        .map(|member| Value::from(member.name.clone()))
                        .unwrap_or(Value::Null),
                );
                map.insert(
                    "field_declaring_type".into(),
                    target
                        .and_then(|member| member.declaring_type.clone())
                        .map(Value::from)
                        .unwrap_or(Value::Null),
                );
                let access = Value::Object(map);
                admit_managed_projection(&access, Some(&mut layout.budget()))?;
                field_accesses.push(access);
            }
        }
        if derives {
            layout.budget().release_transient();
        }
    }
    Ok(Edges {
        call_edges,
        field_accesses,
    })
}

/// The member an operand names, if the operand kind can name that member's kind.
fn named_target<'a>(
    members: &'a HashMap<String, MemberCore>,
    operand_kind: &str,
    operand: &str,
) -> Option<&'a MemberCore> {
    members
        .get(operand)
        .filter(|member| nameable(operand_kind, member.kind))
}

fn caller_name(method: &EdgeMethod<'_>) -> String {
    match method.declaring_type {
        None => method.name.to_string(),
        Some(declaring) => format!("{declaring}.{}", method.name),
    }
}

/// JSON bytes of `callerName`, from its parts: the joining dot adds one byte.
fn caller_name_bytes(method: &EdgeMethod<'_>) -> i64 {
    match method.declaring_type {
        None => json_string_byte_length(method.name, None) as i64,
        Some(declaring) => {
            json_string_byte_length(declaring, None) as i64
                + json_string_byte_length(method.name, None) as i64
                - 1
        }
    }
}
