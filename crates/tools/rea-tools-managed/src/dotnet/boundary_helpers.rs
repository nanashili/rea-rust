//! Managed/native boundary row parsers and projections.
//!
//! Port of `src/dotnet/ManagedNativeBoundaryHelpers.ts`. ModuleRef, Field,
//! MethodDef and ImplMap rows become schema-ordered JSON projections; the CLI
//! header becomes the native summary. Objects are built in schema key order so
//! `managedNativeBoundaryInspectionSchema.parse(...)` is an identity.

use std::collections::HashMap;

use serde_json::Value;

use super::Target;
use super::budget::admit_managed_projection;
use super::failure::{ManagedParseIssue, ReadResult, read_managed_value};
use super::heaps::{
    metadata_coded_token, metadata_coded_token_invalid_reason, metadata_row_cursor, metadata_token,
    read_metadata_string,
};
use super::inventory::{ManagedMetadataInventory, managed_table_row_counts};
use super::layout::ManagedMetadataLayout;
use super::pe_reader::{
    ManagedCliHeader, ManagedPeLayout, managed_cli_32bit_requirement,
    managed_cli_is_mixed_clr_native,
};

/// A member core fact shared by the ImplMap and native-implementation passes.
#[derive(Clone)]
pub struct MemberCore {
    pub token: String,
    pub row_offset: i64,
    pub kind: &'static str,
    pub name: String,
    pub flags: u32,
    pub impl_flags: Option<u32>,
    pub rva: Option<u32>,
}

/// Ordered member collection preserving `new Map([...fields, ...methods])`
/// insertion order while supporting lookup by token.
#[derive(Default)]
pub struct MemberTable {
    pub order: Vec<MemberCore>,
    index: HashMap<String, usize>,
}

impl MemberTable {
    fn insert(&mut self, member: MemberCore) {
        match self.index.get(&member.token).copied() {
            Some(position) => self.order[position] = member,
            None => {
                self.index.insert(member.token.clone(), self.order.len());
                self.order.push(member);
            }
        }
    }

    pub fn get(&self, token: &str) -> Option<&MemberCore> {
        self.index.get(token).map(|position| &self.order[*position])
    }
}

/// `flagsHex(value)`: `0x` plus four lowercase hex digits.
fn flags_hex(value: u32) -> String {
    format!("0x{value:04x}")
}

/// `parseModuleRefs(bytes, layout, heapExtent, issues)`.
pub fn parse_module_refs(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    heap_extent: i64,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<Vec<Value>> {
    let mut refs: Vec<Value> = Vec::new();
    let row_count = layout.table(26).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=row_count {
        read_managed_value(
            || {
                let mut cursor = metadata_row_cursor(bytes, layout, 26, row)?;
                let name = read_metadata_string(
                    bytes,
                    layout,
                    cursor.read_index(layout.string_index_size)?,
                    heap_extent,
                )?;
                refs.push(serde_json::json!({
                    "token": metadata_token(26, row),
                    "row_offset": cursor.start,
                    "name": name,
                }));
                Ok(())
            },
            issues,
        )?;
    }
    Ok(refs)
}

/// `parseFields(bytes, layout, heapExtent, issues)`.
pub fn parse_fields(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    heap_extent: i64,
    issues: &mut Vec<ManagedParseIssue>,
    members: &mut MemberTable,
) -> ReadResult<()> {
    let row_count = layout.table(4).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=row_count {
        read_managed_value(
            || {
                let mut cursor = metadata_row_cursor(bytes, layout, 4, row)?;
                let flags = cursor.read_u16()? as u32;
                let name = read_metadata_string(
                    bytes,
                    layout,
                    cursor.read_index(layout.string_index_size)?,
                    heap_extent,
                )?;
                cursor.read_index(layout.blob_index_size)?;
                let token = metadata_token(4, row);
                members.insert(MemberCore {
                    token,
                    row_offset: cursor.start,
                    kind: "field",
                    name,
                    flags,
                    impl_flags: None,
                    rva: None,
                });
                Ok(())
            },
            issues,
        )?;
    }
    Ok(())
}

/// `parseMethods(bytes, layout, heapExtent, issues)`.
pub fn parse_methods(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    heap_extent: i64,
    issues: &mut Vec<ManagedParseIssue>,
    members: &mut MemberTable,
) -> ReadResult<()> {
    let row_count = layout.table(6).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=row_count {
        read_managed_value(
            || {
                let mut cursor = metadata_row_cursor(bytes, layout, 6, row)?;
                let rva = cursor.read_u32()?;
                let impl_flags = cursor.read_u16()? as u32;
                let flags = cursor.read_u16()? as u32;
                let name = read_metadata_string(
                    bytes,
                    layout,
                    cursor.read_index(layout.string_index_size)?,
                    heap_extent,
                )?;
                cursor.read_index(layout.blob_index_size)?;
                cursor.read_index(layout.table_index_size(8))?;
                let token = metadata_token(6, row);
                members.insert(MemberCore {
                    token,
                    row_offset: cursor.start,
                    kind: "method",
                    name,
                    flags,
                    impl_flags: Some(impl_flags),
                    rva: Some(rva),
                });
                Ok(())
            },
            issues,
        )?;
    }
    Ok(())
}

/// `parseImplMaps({ bytes, layout, heapExtent, modules, members, issues })`.
/// `parseImplMaps({ bytes, layout, heapExtent, modules, members, issues })`.
pub fn parse_impl_maps(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    heap_extent: i64,
    modules: &[Value],
    members: &MemberTable,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<Vec<Value>> {
    // `new Map(modules.map(m => [m.token, m]))`: token -> module name.
    let mut module_names: HashMap<String, String> = HashMap::new();
    for module in modules {
        if let (Some(token), Some(name)) = (
            module.get("token").and_then(Value::as_str),
            module.get("name").and_then(Value::as_str),
        ) {
            module_names
                .entry(token.to_string())
                .or_insert_with(|| name.to_string());
        }
    }
    let mut imports: Vec<Value> = Vec::new();
    let row_count = layout.table(28).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=row_count {
        // The row reader pushes its own validation issues; a sub-buffer keeps
        // that ordering ahead of any failure `read_managed_value` appends.
        let mut row_issues: Vec<ManagedParseIssue> = Vec::new();
        let before_len = issues.len();
        read_managed_value(
            || {
                let mut cursor = metadata_row_cursor(bytes, layout, 28, row)?;
                let mapping_flags = cursor.read_u16()? as u32;
                let member_forwarded_offset = cursor.offset();
                let member_forwarded_raw =
                    cursor.read_index(layout.coded_index_size("MemberForwarded"))?;
                let member_forwarded_reason = metadata_coded_token_invalid_reason(
                    member_forwarded_raw,
                    1,
                    &[Some(4), Some(6)],
                    &layout.row_counts,
                );
                if member_forwarded_reason.is_some() || member_forwarded_raw == 0 {
                    row_issues.push(ManagedParseIssue {
                        code: "invalid-row",
                        scope: format!("metadata.ImplMap:{}", metadata_token(28, row)),
                        offset: Some(member_forwarded_offset as u64),
                        detail: match &member_forwarded_reason {
                            None => "ImplMap MemberForwarded coded index 0x0 is null, but the column must reference a Field or MethodDef row".to_string(),
                            Some(reason) => format!(
                                "ImplMap MemberForwarded coded index 0x{:x} is invalid: {reason}",
                                member_forwarded_raw
                            ),
                        },
                    });
                }
                let member_token = metadata_coded_token(
                    member_forwarded_raw,
                    1,
                    &[Some(4), Some(6)],
                    &layout.row_counts,
                );
                let import_name = read_metadata_string(
                    bytes,
                    layout,
                    cursor.read_index(layout.string_index_size)?,
                    heap_extent,
                )?;
                let import_scope_offset = cursor.offset();
                let import_scope_row = cursor.read_index(layout.table_index_size(26))?;
                let module_count = layout.table(26).map(|t| t.row_count).unwrap_or(0);
                let valid_import_scope =
                    (import_scope_row as i64) > 0 && (import_scope_row as i64) <= module_count;
                if !valid_import_scope {
                    row_issues.push(ManagedParseIssue {
                        code: "invalid-row",
                        scope: format!("metadata.ImplMap:{}", metadata_token(28, row)),
                        offset: Some(import_scope_offset as u64),
                        detail: format!(
                            "ImplMap ImportScope row {import_scope_row} must reference a ModuleRef row between 1 and {module_count}"
                        ),
                    });
                }
                let import_scope_token = if valid_import_scope {
                    Some(metadata_token(26, import_scope_row as i64))
                } else {
                    None
                };
                let member = member_token.as_ref().and_then(|token| members.get(token));
                let import_scope_name = match &import_scope_token {
                    None => Value::Null,
                    Some(token) => module_names
                        .get(token)
                        .map(|name| Value::from(name.clone()))
                        .unwrap_or(Value::Null),
                };
                imports.push(serde_json::json!({
                    "token": metadata_token(28, row),
                    "row_offset": cursor.start,
                    "mapping_flags": mapping_flags,
                    "mapping_flags_hex": flags_hex(mapping_flags),
                    "member_token": token_value(&member_token),
                    "member_kind": member.map(|m| m.kind).unwrap_or("unknown"),
                    "member_name": member.map(|m| Value::from(m.name.clone())).unwrap_or(Value::Null),
                    "import_name": import_name,
                    "import_scope_token": token_value(&import_scope_token),
                    "import_scope_name": import_scope_name,
                    "no_mangle": (mapping_flags & 0x0001) != 0,
                    "char_set": char_set(mapping_flags),
                    "call_convention": call_convention(mapping_flags),
                    "supports_last_error": (mapping_flags & 0x0040) != 0,
                    "best_fit": best_fit(mapping_flags),
                    "throw_on_unmappable_char": throw_on_unmappable(mapping_flags),
                    "verification": "managed-declaration-only",
                }));
                Ok(())
            },
            issues,
        )?;
        merge_row_issues(issues, row_issues, before_len);
    }
    Ok(imports)
}

/// Keep a row reader's self-reported issues ahead of a single failure issue
/// `read_managed_value` appended for the same row. `before_len` is the length
/// of `issues` before the `read_managed_value` call.
fn merge_row_issues(
    issues: &mut Vec<ManagedParseIssue>,
    row_issues: Vec<ManagedParseIssue>,
    before_len: usize,
) {
    if row_issues.is_empty() {
        return;
    }
    if issues.len() > before_len {
        let failure = issues.split_off(before_len);
        issues.extend(row_issues);
        issues.extend(failure);
    } else {
        issues.extend(row_issues);
    }
}
fn token_value(token: &Option<String>) -> Value {
    match token {
        Some(token) => Value::from(token.clone()),
        None => Value::Null,
    }
}

fn char_set(flags: u32) -> &'static str {
    match flags & 0x0006 {
        0x0000 => "not-specified",
        0x0002 => "ansi",
        0x0004 => "unicode",
        0x0006 => "auto",
        _ => "unknown",
    }
}

fn call_convention(flags: u32) -> &'static str {
    match flags & 0x0700 {
        0x0000 => "not-specified",
        0x0100 => "winapi",
        0x0200 => "cdecl",
        0x0300 => "stdcall",
        0x0400 => "thiscall",
        0x0500 => "fastcall",
        _ => "unknown",
    }
}

fn best_fit(flags: u32) -> &'static str {
    match flags & 0x0030 {
        0x0000 => "assembly-default",
        0x0010 => "enabled",
        0x0020 => "disabled",
        _ => "unknown",
    }
}

fn throw_on_unmappable(flags: u32) -> &'static str {
    match flags & 0x3000 {
        0x0000 => "assembly-default",
        0x1000 => "enabled",
        0x2000 => "disabled",
        _ => "unknown",
    }
}

/// `nativeImplementations(methods, pinvokeTokens)`.
pub fn native_implementations(members: &MemberTable, pinvoke_tokens: &[String]) -> Vec<Value> {
    let mut implementations: Vec<Value> = Vec::new();
    for method in &members.order {
        if method.kind != "method" {
            continue;
        }
        let impl_flags = method.impl_flags.unwrap_or(0);
        let code_type = code_type_for(impl_flags);
        let managed_kind = managed_kind_for(impl_flags);
        let pinvoke_declared = pinvoke_tokens.iter().any(|token| token == &method.token)
            || (method.flags & 0x2000) != 0;
        if !pinvoke_declared && code_type == "il" && managed_kind == "managed" {
            continue;
        }
        let body_interpretation =
            if code_type == "il" && managed_kind == "managed" && !pinvoke_declared {
                "managed-cil"
            } else if method.rva == Some(0) {
                "not-file-backed"
            } else {
                "native-or-runtime"
            };
        implementations.push(serde_json::json!({
            "token": method.token,
            "row_offset": method.row_offset,
            "name": method.name,
            "rva": method.rva.unwrap_or(0),
            "flags": method.flags,
            "impl_flags": impl_flags,
            "code_type": code_type,
            "managed_kind": managed_kind,
            "pinvoke_declared": pinvoke_declared,
            "boundary_kind": boundary_kind(pinvoke_declared, code_type, managed_kind),
            "body_interpretation": body_interpretation,
        }));
    }
    implementations
}

fn code_type_for(impl_flags: u32) -> &'static str {
    match impl_flags & 0x0003 {
        0x0000 => "il",
        0x0001 => "native",
        0x0002 => "optil",
        0x0003 => "runtime",
        _ => "unknown",
    }
}

fn managed_kind_for(impl_flags: u32) -> &'static str {
    match impl_flags & 0x0004 {
        0x0000 => "managed",
        0x0004 => "unmanaged",
        _ => "unknown",
    }
}

fn boundary_kind(pinvoke_declared: bool, code_type: &str, managed_kind: &str) -> &'static str {
    if pinvoke_declared {
        return "pinvoke";
    }
    if code_type == "native" {
        return "native-body";
    }
    if code_type == "runtime" {
        return "runtime-provided";
    }
    if managed_kind == "unmanaged" {
        return "unmanaged-method";
    }
    "mixed-or-unknown"
}

/// `cliNative(cli)`.
pub fn cli_native(cli: Option<&ManagedCliHeader>) -> Value {
    match cli {
        None => Value::Null,
        Some(cli) => serde_json::json!({
            "il_only": (cli.flags & 0x0000_0001) != 0,
            "requires_32bit": managed_cli_32bit_requirement(cli.flags) == "required",
            "strong_name_signed": (cli.flags & 0x0000_0008) != 0,
            "native_entry_point": (cli.flags & 0x0000_0010) != 0,
            "ready_to_run_signature": cli.ready_to_run_signature,
            "managed_native_header_rva": cli.managed_native_header.rva,
            "managed_native_header_size": cli.managed_native_header.size,
        }),
    }
}

/// `nativeBoundarySummary(cli, counts)`.
pub fn native_boundary_summary(
    cli: Option<&ManagedCliHeader>,
    module_ref_count: usize,
    pinvoke_import_count: usize,
    native_implementation_count: usize,
) -> Value {
    let ready_to_run = match cli {
        Some(cli) => Value::Bool(cli.ready_to_run_signature),
        None => Value::Null,
    };
    let mixed = match cli {
        None => Value::Null,
        Some(cli) => Value::Bool(
            managed_cli_is_mixed_clr_native(cli)
                || cli.managed_native_header.rva != 0
                || cli.managed_native_header.size != 0
                || (cli.flags & 0x0000_0010) != 0,
        ),
    };
    serde_json::json!({
        "module_ref_count": module_ref_count,
        "pinvoke_import_count": pinvoke_import_count,
        "native_implementation_count": native_implementation_count,
        "ready_to_run": ready_to_run,
        "mixed_mode_or_native_header": mixed,
    })
}

/// Inputs for `buildNativeBoundaryInspection`.
pub struct BoundaryInspectionContext<'a> {
    pub target: &'a Target<'a>,
    pub bytes: &'a [u8],
    pub pe: &'a ManagedPeLayout,
    pub layout: &'a ManagedMetadataLayout,
    pub inventory: &'a ManagedMetadataInventory,
    pub module_refs: Vec<Value>,
    pub imports: Vec<Value>,
    pub implementations: Vec<Value>,
    pub issues: Vec<ManagedParseIssue>,
}

/// `buildNativeBoundaryInspection(context)`: the schema-ordered success result,
/// charged against the shared budget.
pub fn build_native_boundary_inspection(
    context: BoundaryInspectionContext<'_>,
) -> ReadResult<Value> {
    let BoundaryInspectionContext {
        target,
        bytes,
        pe,
        layout,
        inventory,
        module_refs,
        imports,
        implementations,
        issues,
    } = context;
    let status = if issues.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let mvid = inventory
        .module
        .as_ref()
        .and_then(|module| module.get("mvid").cloned())
        .unwrap_or(Value::Null);
    let module_ref_count = module_refs.len();
    let pinvoke_import_count = imports.len();
    let native_implementation_count = implementations.len();
    let value = serde_json::json!({
        "artifact": {
            "path": target.path,
            "sha256": target.sha256,
            "byte_length": bytes.len(),
            "format": "pe",
        },
        "module": inventory.module.clone().unwrap_or(Value::Null),
        "metadata": {
            "status": status,
            "version": layout.version,
            "table_row_counts": managed_table_row_counts(layout),
        },
        "identity_scope": {
            "token_identity": "build-local",
            "requires_artifact_sha256": target.sha256,
            "requires_mvid": mvid,
        },
        "cli_native": cli_native(pe.cli.as_ref()),
        "module_refs": module_refs,
        "pinvoke_imports": imports,
        "native_implementations": implementations,
        "summary": native_boundary_summary(
            pe.cli.as_ref(),
            module_ref_count,
            pinvoke_import_count,
            native_implementation_count,
        ),
        "coverage": {
            "state": status,
            "issues": issues.iter().map(ManagedParseIssue::to_value).collect::<Vec<_>>(),
        },
        "limitations": [
            "P/Invoke rows prove managed import declarations only; this inspection does not verify that a native library, export, thunk, or provider-qualified function exists.",
            "Managed metadata tokens are build-local coordinates and are only meaningful with the reported artifact SHA-256 and MVID.",
            "ReadyToRun, NativeAOT, C++/CLI, and IL2CPP native semantics require separately selected native-provider evidence; this tool does not translate managed tokens into native addresses.",
        ],
    });
    let mut budget = layout.budget();
    admit_managed_projection(&value, Some(&mut budget))?;
    drop(budget);
    Ok(value)
}
