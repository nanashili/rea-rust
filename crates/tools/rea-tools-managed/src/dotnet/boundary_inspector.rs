//! Managed/native boundary inspection from local PE/CLI bytes.
//!
//! Port of `src/dotnet/ManagedNativeBoundaryInspector.ts`. Returns exactly the
//! JSON object the TS `inspectManagedNativeBoundariesBytes` returns.

use serde_json::Value;

use super::Target;
use super::boundary_helpers::{
    BoundaryInspectionContext, MemberTable, build_native_boundary_inspection, cli_native,
    native_boundary_summary, native_implementations, parse_fields, parse_impl_maps, parse_methods,
    parse_module_refs,
};
use super::budget::admit_managed_projection;
use super::failure::{ManagedParseIssue, ReadError, ReadResult};
use super::inventory::{
    ManagedMetadataInventory, read_managed_metadata_inventory, read_managed_resource_directory,
};
use super::layout::{ManagedMetadataLayout, read_managed_metadata_layout};
use super::pe_reader::{
    CliDirectoryState, ManagedCliHeader, ManagedPeLayout, read_managed_pe_layout,
};
use super::type_member_lists::read_type_member_list_facts;

/// `emptyInspection(target, bytes, classification, { cli, issues })`: a PE whose
/// CLI metadata is absent or unreadable.
fn empty_inspection(
    target: &Target<'_>,
    bytes: &[u8],
    classification: &str,
    cli: Option<&ManagedCliHeader>,
    issues: &[ManagedParseIssue],
) -> ReadResult<Value> {
    let status = if issues.iter().any(|issue| issue.code == "resource-limit") {
        "partial"
    } else if classification == "malformed" {
        "malformed"
    } else {
        "absent"
    };
    let value = serde_json::json!({
        "artifact": {
            "path": target.path,
            "sha256": target.sha256,
            "byte_length": bytes.len(),
            "format": "pe",
        },
        "module": Value::Null,
        "metadata": {
            "status": status,
            "version": Value::Null,
            "table_row_counts": serde_json::Map::new(),
        },
        "identity_scope": {
            "token_identity": "build-local",
            "requires_artifact_sha256": target.sha256,
            "requires_mvid": Value::Null,
        },
        "cli_native": cli_native(cli),
        "module_refs": [],
        "pinvoke_imports": [],
        "native_implementations": [],
        "summary": native_boundary_summary(cli, 0, 0, 0),
        "coverage": {
            "state": "unavailable",
            "issues": issues.iter().map(ManagedParseIssue::to_value).collect::<Vec<_>>(),
        },
        "limitations": [
            "No CLI metadata was admitted; native boundary declarations are unavailable.",
            "Static inspection does not load or execute target code, so native export resolution is not performed.",
        ],
    });
    admit_managed_projection(&value, None)?;
    Ok(value)
}

/// `readBoundaryInventory(bytes, pe, cli, issues)`.
fn read_boundary_inventory(
    bytes: &[u8],
    pe: &ManagedPeLayout,
    cli: &ManagedCliHeader,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<(ManagedMetadataLayout, ManagedMetadataInventory)> {
    let metadata_offset = pe
        .rva_to_offset(bytes, cli.metadata.rva, cli.metadata.size, "cli.metadata")
        .map_err(ReadError::from)?;
    let layout = read_managed_metadata_layout(bytes, metadata_offset, cli.metadata.size)
        .map_err(ReadError::from)?;
    let member_lists = read_type_member_list_facts(bytes, &layout).map_err(ReadError::from)?;
    let resource_directory = read_managed_resource_directory(bytes, pe, issues)?;
    let inventory =
        read_managed_metadata_inventory(bytes, &layout, resource_directory, &member_lists)?;
    Ok((layout, inventory))
}

/// Second-stage boundary parse: build the success inspection from the admitted
/// layout and inventory. A reader failure propagates to the caller.
fn build_boundary(
    bytes: &[u8],
    pe: &ManagedPeLayout,
    layout: &ManagedMetadataLayout,
    inventory: &ManagedMetadataInventory,
    target: &Target<'_>,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<Value> {
    let heap_extent = layout.strings.size.max(layout.blob.size);
    issues.extend(inventory.issues.iter().cloned());
    let module_refs = parse_module_refs(bytes, layout, heap_extent, issues)?;
    let mut members = MemberTable::default();
    parse_fields(bytes, layout, heap_extent, issues, &mut members)?;
    parse_methods(bytes, layout, heap_extent, issues, &mut members)?;
    let imports = parse_impl_maps(bytes, layout, heap_extent, &module_refs, &members, issues)?;
    // `new Set(imports.map(member_token).filter(non-null))`.
    let pinvoke_tokens: Vec<String> = imports
        .iter()
        .filter_map(|import| import.get("member_token").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    let implementations = native_implementations(&members, &pinvoke_tokens);
    build_native_boundary_inspection(BoundaryInspectionContext {
        target,
        bytes,
        pe,
        layout,
        inventory,
        module_refs,
        imports,
        implementations,
        issues: issues.clone(),
    })
}

/// `inspectManagedNativeBoundariesBytes(bytes, target)`.
pub fn inspect_managed_native_boundaries_bytes(
    bytes: &[u8],
    target: &Target<'_>,
) -> ReadResult<Value> {
    let pe = read_managed_pe_layout(bytes)?;
    let cli = match pe.cli.as_ref() {
        Some(cli) => cli.clone(),
        None => {
            let classification = if pe.cli_directory_state != CliDirectoryState::Absent {
                "malformed"
            } else {
                "not-managed"
            };
            let issues: Vec<ManagedParseIssue> = pe.cli_issue.iter().cloned().collect();
            return empty_inspection(target, bytes, classification, None, &issues);
        }
    };

    let mut issues: Vec<ManagedParseIssue> = Vec::new();
    let (layout, inventory) = match read_boundary_inventory(bytes, &pe, &cli, &mut issues) {
        Ok(result) => result,
        Err(ReadError::Reader(failure)) => {
            return empty_inspection(target, bytes, "malformed", Some(&cli), &[failure.issue]);
        }
        Err(internal @ ReadError::Internal(_)) => return Err(internal),
    };

    match build_boundary(bytes, &pe, &layout, &inventory, target, &mut issues) {
        Ok(value) => Ok(value),
        Err(ReadError::Reader(failure)) => {
            // `[...issues, cause.issue]`.
            let mut combined = issues.clone();
            combined.push(failure.issue);
            empty_inspection(target, bytes, "malformed", Some(&cli), &combined)
        }
        Err(internal @ ReadError::Internal(_)) => Err(internal),
    }
}
