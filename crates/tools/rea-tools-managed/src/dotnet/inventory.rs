//! Identity-table inventory shared by every managed inspection facet.
//!
//! Port of `src/dotnet/ManagedMetadataInventory.ts`. Rows are the exact JSON
//! objects the TS producer returns, built in schema key order so a later
//! `managedArtifactInspectionSchema.parse(...)` is an identity.

use serde_json::{Map, Value};

use super::failure::{
    ManagedParseIssue, ReadError, ReadResult, read_managed_value, unique_managed_parse_issues,
};
use super::heaps::metadata_token;
use super::inventory_rows::{
    ResourceContext, read_assembly, read_assembly_reference, read_custom_attribute, read_module,
    read_resource,
};
use super::layout::{METADATA_TABLE_NAMES, ManagedMetadataLayout, MetadataTableLayout};
use super::member_ownership::MemberOwnershipCache;
use super::pe_reader::ManagedPeLayout;
use super::type_member_lists::TypeMemberListFacts;

/// `ManagedResourceDirectory`: file offset and size of the CLI resources.
#[derive(Clone, Copy, Debug)]
pub struct ManagedResourceDirectory {
    pub offset: i64,
    pub size: i64,
}

/// `ManagedMetadataInventory`. Rows are the exact JSON objects the TS producer
/// returns (schema key order).
pub struct ManagedMetadataInventory {
    pub module: Option<Value>,
    pub assembly: Option<Value>,
    pub target_frameworks: Vec<String>,
    pub reference_names: Vec<String>,
    pub references: Vec<Value>,
    pub resources: Vec<Value>,
    pub attributes: Vec<Value>,
    pub issues: Vec<ManagedParseIssue>,
}

/// `readManagedResourceDirectory(pe, issues)`.
///
/// The TS receives the PE layout; the Rust `rva_to_offset` method also needs
/// the backing bytes, so they are threaded through here.
pub fn read_managed_resource_directory(
    bytes: &[u8],
    pe: &ManagedPeLayout,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<Option<ManagedResourceDirectory>> {
    let resources = match pe.cli.as_ref() {
        Some(cli) => cli.resources,
        None => return Ok(None),
    };
    if resources.rva == 0 && resources.size == 0 {
        return Ok(None);
    }
    let size = resources.size;
    let result = read_managed_value(
        || {
            let offset = pe
                .rva_to_offset(bytes, resources.rva, resources.size, "cli.resources")
                .map_err(ReadError::from)?;
            Ok(ManagedResourceDirectory { offset, size })
        },
        issues,
    )?;
    Ok(result)
}

/// The shared heap extent used by most readers: `max(strings.size, blob.size)`.
fn heap_extent(layout: &ManagedMetadataLayout) -> i64 {
    layout.strings.size.max(layout.blob.size)
}

/// `readRows(descriptor, read)`: one-based rows 1..=rowCount, discarding `None`.
fn read_rows<T>(
    descriptor: Option<&MetadataTableLayout>,
    mut read: impl FnMut(i64) -> ReadResult<Option<T>>,
) -> ReadResult<Vec<T>> {
    let total = descriptor.map(|t| t.row_count).unwrap_or(0);
    let mut items = Vec::new();
    for index in 0..total {
        if let Some(item) = read(index + 1)? {
            items.push(item);
        }
    }
    Ok(items)
}

fn validate_identity_table_counts(
    layout: &ManagedMetadataLayout,
    issues: &mut Vec<ManagedParseIssue>,
) {
    let module_rows = layout.table(0).map(|t| t.row_count).unwrap_or(0);
    if module_rows != 1 {
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: "metadata.Module".to_string(),
            offset: layout.table(0).map(|t| t.offset as u64),
            detail: format!("Module table must contain exactly one row; found {module_rows}"),
        });
    }

    let assembly_rows = layout.table(32).map(|t| t.row_count).unwrap_or(0);
    if assembly_rows > 1 {
        issues.push(ManagedParseIssue {
            code: "invalid-row",
            scope: "metadata.Assembly".to_string(),
            offset: layout.table(32).map(|t| t.offset as u64),
            detail: format!("Assembly table can contain at most one row; found {assembly_rows}"),
        });
    }
}

fn read_references(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<(Vec<Value>, Vec<String>)> {
    let extent = heap_extent(layout);
    let references = read_rows(layout.table(35), |row| {
        read_managed_value(
            || read_assembly_reference(bytes, layout, row, extent).map_err(ReadError::from),
            issues,
        )
    })?;
    // `[...new Set(references.map(({ name }) => name))].sort()`: Set keeps
    // first-seen order, then `.sort()` re-orders by UTF-16 code unit.
    let mut names: Vec<String> = Vec::new();
    for reference in &references {
        if let Some(name) = reference.get("name").and_then(Value::as_str) {
            if !names.iter().any(|existing| existing == name) {
                names.push(name.to_string());
            }
        }
    }
    names.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
    Ok((references, names))
}

/// Append a row reader's self-reported issues so they stay ahead of any single
/// failure issue `read_managed_value` appended for the same row.
///
/// `read_managed_value` appends at most one issue, and only on a captured
/// (non-limit) reader failure. `before_len` is the length of `issues` before
/// the `read_managed_value` call. The TS pushes the reader's own issues first
/// and appends the thrown failure afterward, so the row's own issues must come
/// before that one trailing failure.
fn merge_row_issues(
    issues: &mut Vec<ManagedParseIssue>,
    row_issues: Vec<ManagedParseIssue>,
    before_len: usize,
) {
    if row_issues.is_empty() {
        return;
    }
    if issues.len() > before_len {
        // One failure issue was appended; move the row's own issues ahead of it.
        let failure = issues.split_off(before_len);
        issues.extend(row_issues);
        issues.extend(failure);
    } else {
        issues.extend(row_issues);
    }
}

fn read_resources(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    resource_directory: Option<ManagedResourceDirectory>,
    issues: &mut Vec<ManagedParseIssue>,
) -> ReadResult<Vec<Value>> {
    let descriptor = layout.table(40);
    let total = descriptor.map(|t| t.row_count).unwrap_or(0);
    let mut items = Vec::new();
    for index in 0..total {
        let row = index + 1;
        let mut row_issues: Vec<ManagedParseIssue> = Vec::new();
        let before_len = issues.len();
        let read = read_managed_value(
            || {
                read_resource(ResourceContext {
                    bytes,
                    layout,
                    row,
                    directory: resource_directory,
                    issues: &mut row_issues,
                })
                .map_err(ReadError::from)
            },
            issues,
        )?;
        merge_row_issues(issues, row_issues, before_len);
        if let Some(item) = read {
            items.push(item);
        }
    }
    Ok(items)
}

fn read_attributes(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    issues: &mut Vec<ManagedParseIssue>,
    member_lists: &TypeMemberListFacts,
    ownership: &MemberOwnershipCache,
) -> ReadResult<(Vec<Value>, Vec<String>)> {
    let extent = heap_extent(layout);
    let descriptor = layout.table(12);
    let total = descriptor.map(|t| t.row_count).unwrap_or(0);
    let mut attributes = Vec::new();
    for index in 0..total {
        let row = index + 1;
        let mut row_issues: Vec<ManagedParseIssue> = Vec::new();
        let before_len = issues.len();
        let read = read_managed_value(
            || {
                read_custom_attribute(
                    bytes,
                    layout,
                    row,
                    extent,
                    &mut row_issues,
                    member_lists,
                    ownership,
                )
                .map_err(ReadError::from)
            },
            issues,
        )?;
        merge_row_issues(issues, row_issues, before_len);
        if let Some(item) = read {
            attributes.push(item);
        }
    }
    // Set<string> of assembly-level TargetFrameworkAttribute decoded strings.
    let mut frameworks: Vec<String> = Vec::new();
    let assembly_parent = metadata_token(32, 1);
    for attribute in &attributes {
        let parent_token = attribute.get("parent_token").and_then(Value::as_str);
        let type_name = attribute.get("type_name").and_then(Value::as_str);
        let decoded = attribute.get("decoded_fixed_string");
        if parent_token == Some(assembly_parent.as_str())
            && type_name == Some("System.Runtime.Versioning.TargetFrameworkAttribute")
        {
            if let Some(Value::String(decoded)) = decoded {
                if !frameworks.iter().any(|value| value == decoded) {
                    frameworks.push(decoded.clone());
                }
            }
        }
    }
    frameworks.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
    Ok((attributes, frameworks))
}

/// `readManagedMetadataInventory(bytes, layout, resourceDirectory, memberLists)`.
pub fn read_managed_metadata_inventory(
    bytes: &[u8],
    layout: &ManagedMetadataLayout,
    resource_directory: Option<ManagedResourceDirectory>,
    member_lists: &TypeMemberListFacts,
) -> ReadResult<ManagedMetadataInventory> {
    let mut issues: Vec<ManagedParseIssue> = member_lists.issues.clone();
    validate_identity_table_counts(layout, &mut issues);
    let extent = heap_extent(layout);
    let module = read_managed_value(
        || read_module(bytes, layout, extent).map_err(ReadError::from),
        &mut issues,
    )?
    .flatten();
    let assembly = read_managed_value(
        || read_assembly(bytes, layout, extent).map_err(ReadError::from),
        &mut issues,
    )?
    .flatten();
    let (references, reference_names) = read_references(bytes, layout, &mut issues)?;
    let resources = read_resources(bytes, layout, resource_directory, &mut issues)?;
    // `declaringTypeForMethod` rebuilds the WeakMap-cached owner table per
    // inventory; one cache for the whole attribute pass reproduces that.
    let ownership = MemberOwnershipCache::default();
    let (attributes, target_frameworks) =
        read_attributes(bytes, layout, &mut issues, member_lists, &ownership)?;
    Ok(ManagedMetadataInventory {
        module,
        assembly,
        target_frameworks,
        reference_names,
        references,
        resources,
        attributes,
        issues: unique_managed_parse_issues(&issues),
    })
}

/// `managedTableRowCounts(layout)`: table name -> row count, in table order.
///
/// `layout.tables` is a `BTreeMap` keyed by table index, so iteration is
/// ascending-index order, equal to the TS `Map` insertion order (built over
/// `index` 0..45).
pub fn managed_table_row_counts(layout: &ManagedMetadataLayout) -> Map<String, Value> {
    let mut map = Map::new();
    for descriptor in layout.tables.values() {
        let name = METADATA_TABLE_NAMES
            .get(descriptor.index)
            .map(|name| (*name).to_string())
            .unwrap_or_else(|| format!("Table{}", descriptor.index));
        map.insert(name, Value::from(descriptor.row_count));
    }
    map
}
