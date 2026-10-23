//! Metadata member, signature, and CIL inspection from local bytes.
//!
//! Port of `src/dotnet/ManagedMemberInspector.ts`. Reads TypeDef/Field/Method/
//! MemberRef/ExportedType rows, decodes signatures and method bodies, derives
//! call edges and field accesses, and reports #US literals, all under one
//! shared representation budget. The returned `Value` is exactly the object
//! `managedMemberInspectionSchema.parse(...)` produces: keys in schema
//! declaration order, defaults applied, and each embedded producer value in its
//! own schema order.

use std::cell::RefCell;
use std::collections::HashSet;

use serde_json::{Map, Value};

use super::Target;
use super::budget::admit_managed_projection;
use super::failure::{
    InternalFailure, ManagedParseIssue, ReadError, ReadResult, append_managed_parse_issues,
    unique_managed_parse_issues,
};
use super::inventory::{
    ManagedMetadataInventory, managed_table_row_counts, read_managed_metadata_inventory,
    read_managed_resource_directory,
};
use super::layout::{ManagedMetadataLayout, read_managed_metadata_layout};
use super::member_core::{ParsedType, ParsedTypes, RowRange, TypeRange, parse_types, type_ranges};
use super::member_rows::{
    EdgeMethod, edges, parse_exported_types, parse_fields, parse_member_refs, parse_methods,
};
use super::method_body::Anchor;
use super::method_specs::edge_targets;
use super::pe_reader::{ManagedPeLayout, read_managed_pe_layout};
use super::type_member_lists::{TypeMemberListFacts, read_type_member_list_facts};
use super::type_name_digests::{DigestFault, managed_type_name_digests};
use super::type_names::TypeNameLookup;
use super::type_references::ManagedTypeReferences;
use super::user_strings::parse_user_strings;

/// `Number.MAX_SAFE_INTEGER`, the default `methodLimit` the provider glue passes.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// `inspectManagedMembersBytes(bytes, target, { typeNames })`.
///
/// `methodOffset`, `methodLimit`, and `userStrings` are fixed to their provider
/// defaults (`0`, `MAX_SAFE_INTEGER`, `true`); the TS `RangeError` guard on the
/// first two can therefore never fire.
pub fn inspect_managed_members_bytes(
    bytes: &[u8],
    target: &Target<'_>,
    type_names: Option<&[String]>,
) -> ReadResult<Value> {
    let method_offset: i64 = 0;
    let method_limit: i64 = MAX_SAFE_INTEGER;
    let read_user_strings = true;

    let pe = read_managed_pe_layout(bytes).map_err(ReadError::from)?;
    if pe.cli.is_none() {
        return Ok(unavailable(
            target,
            bytes,
            pe.cli_issue.as_ref(),
            type_names,
        ));
    }

    // The TS try/catch turns any escaping `ManagedReaderFailure` into an
    // unavailable result; other failures rethrow.
    match inspect(
        bytes,
        target,
        type_names,
        &pe,
        method_offset,
        method_limit,
        read_user_strings,
    ) {
        Ok(value) => Ok(value),
        Err(ReadError::Reader(failure)) => {
            Ok(unavailable(target, bytes, Some(&failure.issue), type_names))
        }
        Err(other) => Err(other),
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect(
    bytes: &[u8],
    target: &Target<'_>,
    type_names: Option<&[String]>,
    pe: &ManagedPeLayout,
    method_offset: i64,
    method_limit: i64,
    read_user_strings: bool,
) -> ReadResult<Value> {
    let issues_cell: RefCell<Vec<ManagedParseIssue>> = RefCell::new(Vec::new());

    // `readMemberInventory(bytes, pe, issues)`.
    let (layout, inventory, member_lists) = read_member_inventory(bytes, pe, &issues_cell)?;
    append_managed_parse_issues(
        &mut issues_cell.borrow_mut(),
        &[inventory.issues.as_slice()],
    );

    let ranges = {
        let mut issues = issues_cell.borrow_mut();
        type_ranges(bytes, &layout, &mut issues, &member_lists)?
    };

    let Selection {
        tokens: selected,
        selection,
        unreadable_names,
    } = select_types(&ranges, type_names);

    let parsed_types = parse_types(bytes, &layout, &ranges)?;
    append_managed_parse_issues(
        &mut issues_cell.borrow_mut(),
        &[parsed_types.issues.as_slice()],
    );

    let exported_types = parse_exported_types(bytes, &layout)?;
    append_managed_parse_issues(
        &mut issues_cell.borrow_mut(),
        &[exported_types.issues.as_slice()],
    );

    // Shared TypeRef source tuples and scope validation, used by both the
    // type-name lookup and the type-name digests.
    let references_cell: RefCell<ManagedTypeReferences> =
        RefCell::new(ManagedTypeReferences::new());

    let (mut signature_type_name, digest_fault) = managed_type_name_digests(
        &layout,
        &issues_cell,
        &parsed_types.types,
        &parsed_types.nesting,
        &references_cell,
        bytes,
    )?;

    let fields = parse_fields(
        bytes,
        &layout,
        &ranges,
        &member_lists,
        &mut signature_type_name,
        selected.as_ref(),
    )?;
    check_fault(&digest_fault)?;

    // `typeNameLookup(bytes, layout, ranges, issues, typeReferences)`.
    let type_name_lookup: RefCell<TypeNameLookup> = RefCell::new(TypeNameLookup::new());
    let member_refs = {
        let mut type_name = |token: Option<&str>| -> ReadResult<Option<String>> {
            type_name_lookup.borrow_mut().lookup(
                bytes,
                &layout,
                &ranges,
                &mut references_cell.borrow_mut(),
                &mut issues_cell.borrow_mut(),
                token,
            )
        };
        parse_member_refs(bytes, &layout, &mut type_name, &mut signature_type_name)?
    };
    check_fault(&digest_fault)?;
    append_managed_parse_issues(
        &mut issues_cell.borrow_mut(),
        &[member_refs.issues.as_slice()],
    );

    let methods = parse_methods(
        bytes,
        &layout,
        pe,
        &ranges,
        &mut signature_type_name,
        &member_lists,
        selected.as_ref(),
        method_offset,
        method_limit,
    )?;
    check_fault(&digest_fault)?;
    append_managed_parse_issues(
        &mut issues_cell.borrow_mut(),
        &[fields.issues.as_slice(), methods.issues.as_slice()],
    );

    // #US literals sit beside the member inventory and carry their own
    // coverage, so their issues never make member facts partial.
    let user_strings = if read_user_strings {
        Some(parse_user_strings(
            bytes,
            &layout,
            &methods.method_anchors,
            methods.unscanned_methods,
            unreadable_names,
        )?)
    } else {
        None
    };

    // `edgeTargets(bytes, layout, methods.methods, [fields.core, memberRefs.core, methods.core])`.
    let cores = [fields.core, member_refs.core, methods.core];
    let targets = edge_targets(bytes, &layout, &methods.method_anchors, &cores)?;
    append_managed_parse_issues(&mut issues_cell.borrow_mut(), &[targets.issues.as_slice()]);

    let incomplete_members = incomplete(&fields.fields, &member_refs.refs, &methods.methods)
        || methods
            .method_statuses
            .iter()
            .any(|status| *status == "partial" || *status == "malformed");

    // `edges(methods.methods, targets.members, managedDecodeBudget(layout))`.
    let edge_methods = edge_methods(&methods.methods, &methods.method_anchors);
    let related = edges(&edge_methods, &targets.members, &layout)?;

    // `types` projection: selected types only, each with its name digest.
    let (types, unnamed_types) = project_types(
        &layout,
        &parsed_types,
        selected.as_ref(),
        &mut signature_type_name,
    )?;
    check_fault(&digest_fault)?;

    let coverage_issues = unique_managed_parse_issues(&issues_cell.borrow());
    let issues_len = issues_cell.borrow().len();

    let result = build_result(ResultInputs {
        target,
        bytes,
        layout: &layout,
        inventory: &inventory,
        types,
        parsed_types: &parsed_types,
        exported_types: exported_types.exported_types,
        fields: fields.fields,
        methods: methods.methods,
        member_refs: member_refs.refs,
        call_edges: related.call_edges,
        field_accesses: related.field_accesses,
        user_strings,
        selection,
        coverage_issues,
        issues_len,
        incomplete_members,
        unnamed_types,
        unreadable_names,
    });

    // `admitManagedProjection(result, managedDecodeBudget(layout))` then
    // `managedMemberInspectionSchema.parse(...)`. The result is already built in
    // schema key order with defaults applied, so no reordering is needed.
    admit_managed_projection(&result, Some(&mut layout.budget())).map_err(ReadError::from)?;
    Ok(result)
}

/// Surface a resource-limit (or internal) failure a digest closure swallowed,
/// reproducing the TS throw that the inspector's try/catch turns into an
/// unavailable result.
fn check_fault(fault: &DigestFault) -> ReadResult<()> {
    if let Some(error) = fault.borrow_mut().take() {
        return Err(error);
    }
    Ok(())
}

/// `readMemberInventory(bytes, pe, issues)`.
fn read_member_inventory(
    bytes: &[u8],
    pe: &ManagedPeLayout,
    issues_cell: &RefCell<Vec<ManagedParseIssue>>,
) -> ReadResult<(
    ManagedMetadataLayout,
    ManagedMetadataInventory,
    TypeMemberListFacts,
)> {
    // `pe.cli` is `Some` here (checked by the caller); a `None` would be the TS
    // `TypeError`, which is unreachable.
    let cli = pe.cli.as_ref().ok_or_else(|| {
        ReadError::Internal(InternalFailure(
            "Managed inventory requires CLI metadata".to_string(),
        ))
    })?;
    let root_offset = pe
        .rva_to_offset(bytes, cli.metadata.rva, cli.metadata.size, "cli.metadata")
        .map_err(ReadError::from)?;
    let layout = read_managed_metadata_layout(bytes, root_offset, cli.metadata.size)
        .map_err(ReadError::from)?;
    let member_lists = read_type_member_list_facts(bytes, &layout).map_err(ReadError::from)?;
    let resource_directory = {
        let mut issues = issues_cell.borrow_mut();
        read_managed_resource_directory(bytes, pe, &mut issues)?
    };
    let inventory =
        read_managed_metadata_inventory(bytes, &layout, resource_directory, &member_lists)?;
    Ok((layout, inventory, member_lists))
}

/// The resolved selection and its coverage facts.
struct Selection {
    tokens: Option<HashSet<String>>,
    selection: Value,
    unreadable_names: i64,
}

/// `selectTypes(ranges, typeNames)`.
fn select_types(ranges: &[TypeRange], type_names: Option<&[String]>) -> Selection {
    let type_names = match type_names {
        Some(names) => names,
        None => {
            return Selection {
                tokens: None,
                selection: Value::Null,
                unreadable_names: 0,
            };
        }
    };
    let requested: HashSet<&str> = type_names.iter().map(String::as_str).collect();
    let mut tokens: HashSet<String> = HashSet::new();
    let mut matched: HashSet<String> = HashSet::new();
    for range in ranges {
        if let Some(full_name) = &range.full_name {
            if requested.contains(full_name.as_str()) {
                tokens.insert(range.token.clone());
                matched.insert(full_name.clone());
            }
        }
    }
    let unreadable_names = ranges
        .iter()
        .filter(|range| range.full_name.is_none())
        .count() as i64;
    let unmatched: Vec<Value> = type_names
        .iter()
        .filter(|name| !matched.contains(name.as_str()))
        .map(|name| Value::from(name.clone()))
        .collect();
    let mut selection = Map::new();
    selection.insert(
        "type_names".into(),
        Value::Array(
            type_names
                .iter()
                .map(|name| Value::from(name.clone()))
                .collect(),
        ),
    );
    selection.insert("unmatched_type_names".into(), Value::Array(unmatched));
    Selection {
        tokens: Some(tokens),
        selection: Value::Object(selection),
        unreadable_names,
    }
}

/// Build the per-method edge inputs from the decoded method values and anchors.
fn edge_methods<'a>(methods: &'a [Value], anchors: &'a [Vec<Anchor>]) -> Vec<EdgeMethod<'a>> {
    methods
        .iter()
        .zip(anchors.iter())
        .map(|(method, anchors)| EdgeMethod {
            token: method.get("token").and_then(Value::as_str).unwrap_or(""),
            name: method.get("name").and_then(Value::as_str).unwrap_or(""),
            declaring_type: method.get("declaring_type").and_then(Value::as_str),
            anchors: anchors.as_slice(),
        })
        .collect()
}

/// Whether any member's signature did not fully decode.
fn incomplete(fields: &[Value], member_refs: &[Value], methods: &[Value]) -> bool {
    let not_decoded = |member: &Value| {
        member
            .get("signature")
            .and_then(|sig| sig.get("parse_status"))
            .and_then(Value::as_str)
            != Some("decoded")
    };
    fields.iter().any(not_decoded)
        || member_refs.iter().any(not_decoded)
        || methods.iter().any(not_decoded)
}

/// Project selected types with their name digests; returns the type values and
/// the count whose name digest is unresolved.
fn project_types(
    layout: &ManagedMetadataLayout,
    parsed_types: &ParsedTypes,
    selected: Option<&HashSet<String>>,
    signature_type_name: &mut super::member_core::SignatureTypeName<'_>,
) -> ReadResult<(Vec<Value>, i64)> {
    let mut types: Vec<Value> = Vec::new();
    let mut unnamed = 0i64;
    for type_row in &parsed_types.types {
        if let Some(selected) = selected {
            if !selected.contains(&type_row.token) {
                continue;
            }
        }
        layout
            .budget()
            .reserve(512, Some(type_row.row_offset as u64))?;
        // `Number.parseInt(type.token.slice(4), 16) * 4`: TypeDef coded index.
        let row = i64::from_str_radix(&type_row.token[4..], 16).unwrap_or(0);
        let name_sha256 = signature_type_name(row * 4).map(|digest| hex(&digest));
        if name_sha256.is_none() {
            unnamed += 1;
        }
        types.push(type_value(type_row, name_sha256));
    }
    Ok((types, unnamed))
}

/// Lowercase hex of a digest.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// One `managedTypeSchema` row in schema key order.
fn type_value(type_row: &ParsedType, name_sha256: Option<String>) -> Value {
    let mut map = Map::new();
    map.insert("token".into(), Value::from(type_row.token.clone()));
    map.insert("row_offset".into(), Value::from(type_row.row_offset));
    map.insert("namespace".into(), Value::from(type_row.namespace.clone()));
    map.insert("name".into(), Value::from(type_row.name.clone()));
    map.insert("full_name".into(), Value::from(type_row.full_name.clone()));
    map.insert(
        "name_sha256".into(),
        name_sha256.map(Value::from).unwrap_or(Value::Null),
    );
    map.insert("flags".into(), Value::from(type_row.flags));
    map.insert(
        "extends_token".into(),
        type_row
            .extends_token
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    map.insert(
        "enclosing_type_token".into(),
        type_row
            .enclosing_type_token
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    map.insert("field_list".into(), row_range_value(&type_row.field_list));
    map.insert("method_list".into(), row_range_value(&type_row.method_list));
    Value::Object(map)
}

fn row_range_value(range: &RowRange) -> Value {
    let mut map = Map::new();
    map.insert(
        "first_row".into(),
        range.first.map(Value::from).unwrap_or(Value::Null),
    );
    map.insert(
        "last_row".into(),
        range.last.map(Value::from).unwrap_or(Value::Null),
    );
    map.insert("count".into(), Value::from(range.count));
    Value::Object(map)
}

struct ResultInputs<'a> {
    target: &'a Target<'a>,
    bytes: &'a [u8],
    layout: &'a ManagedMetadataLayout,
    inventory: &'a ManagedMetadataInventory,
    types: Vec<Value>,
    parsed_types: &'a ParsedTypes,
    exported_types: Vec<Value>,
    fields: Vec<Value>,
    methods: Vec<Value>,
    member_refs: Vec<Value>,
    call_edges: Vec<Value>,
    field_accesses: Vec<Value>,
    user_strings: Option<Value>,
    selection: Value,
    coverage_issues: Vec<ManagedParseIssue>,
    issues_len: usize,
    incomplete_members: bool,
    unnamed_types: i64,
    unreadable_names: i64,
}

/// Build the member inspection object in `managedMemberInspectionSchema` key
/// order with defaults applied.
fn build_result(inputs: ResultInputs<'_>) -> Value {
    let mut map = Map::new();
    // signature_resolution (schema position 1).
    map.insert("signature_resolution".into(), Value::from("type-names-v1"));
    map.insert(
        "artifact".into(),
        artifact_value(inputs.target, inputs.bytes),
    );
    let module = inputs.inventory.module.clone().unwrap_or(Value::Null);
    map.insert("module".into(), module.clone());
    map.insert(
        "metadata".into(),
        metadata_value(inputs.layout, inputs.issues_len),
    );
    map.insert(
        "identity_scope".into(),
        identity_scope_value(inputs.target, &module),
    );
    map.insert("types".into(), Value::Array(inputs.types));
    map.insert(
        "nesting_read".into(),
        Value::from(inputs.parsed_types.nesting.complete),
    );
    map.insert("exported_types".into(), Value::Array(inputs.exported_types));
    map.insert("fields".into(), Value::Array(inputs.fields));
    map.insert("methods".into(), Value::Array(inputs.methods));
    map.insert("member_refs".into(), Value::Array(inputs.member_refs));
    map.insert("call_edges".into(), Value::Array(inputs.call_edges));
    map.insert("field_accesses".into(), Value::Array(inputs.field_accesses));
    map.insert(
        "user_strings".into(),
        inputs.user_strings.unwrap_or(Value::Null),
    );
    map.insert("selection".into(), inputs.selection.clone());
    map.insert(
        "coverage".into(),
        coverage_value(
            inputs.issues_len,
            inputs.incomplete_members,
            &inputs.coverage_issues,
        ),
    );
    map.insert(
        "limitations".into(),
        limitations_value(
            inputs.unnamed_types,
            &inputs.selection,
            inputs.unreadable_names,
        ),
    );
    Value::Object(map)
}

fn artifact_value(target: &Target<'_>, bytes: &[u8]) -> Value {
    let mut map = Map::new();
    map.insert("path".into(), Value::from(target.path));
    map.insert("sha256".into(), Value::from(target.sha256));
    map.insert("byte_length".into(), Value::from(bytes.len()));
    map.insert("format".into(), Value::from("pe"));
    Value::Object(map)
}

fn metadata_value(layout: &ManagedMetadataLayout, issues_len: usize) -> Value {
    let mut map = Map::new();
    map.insert(
        "status".into(),
        Value::from(if issues_len == 0 {
            "complete"
        } else {
            "partial"
        }),
    );
    map.insert("version".into(), Value::from(layout.version.clone()));
    map.insert(
        "table_row_counts".into(),
        Value::Object(managed_table_row_counts(layout)),
    );
    Value::Object(map)
}

fn identity_scope_value(target: &Target<'_>, module: &Value) -> Value {
    let mut map = Map::new();
    map.insert("token_identity".into(), Value::from("build-local"));
    map.insert(
        "requires_artifact_sha256".into(),
        Value::from(target.sha256),
    );
    map.insert(
        "requires_mvid".into(),
        module.get("mvid").cloned().unwrap_or(Value::Null),
    );
    Value::Object(map)
}

fn coverage_value(issues_len: usize, incomplete: bool, issues: &[ManagedParseIssue]) -> Value {
    let mut map = Map::new();
    map.insert(
        "state".into(),
        Value::from(if issues_len == 0 && !incomplete {
            "complete"
        } else {
            "partial"
        }),
    );
    map.insert(
        "issues".into(),
        Value::Array(issues.iter().map(ManagedParseIssue::to_value).collect()),
    );
    Value::Object(map)
}

fn limitations_value(unnamed_types: i64, selection: &Value, unreadable_names: i64) -> Value {
    let mut out: Vec<Value> = Vec::new();
    if unnamed_types != 0 {
        out.push(Value::from(format!(
            "{unnamed_types} returned TypeDef name identity(s) remain unresolved; incomplete, missing, contradictory, cyclic or over-deep enclosing facts cannot be repaired by bare display names."
        )));
    }
    out.push(Value::from(
        "Metadata tokens are build-local coordinates and are only meaningful with the reported artifact SHA-256 and MVID.",
    ));
    out.push(Value::from(
        "CIL instruction anchors are decoded from file-backed method bodies only; no target assembly is loaded or executed.",
    ));
    out.push(Value::from(
        "Exported types are reported from ExportedType rows as declared; forwarded types are not resolved in their implementing assemblies.",
    ));
    out.push(Value::from(
        "User strings are the #US literals loaded by ldstr in the inspected method bodies, with their own coverage; instruction anchors and normalized CIL digests keep their build-local tokens.",
    ));
    out.push(Value::from(
        "Member signatures decode ECMA-335 primitive, class, valuetype, generic instantiation, generic variable, pointer, byref, single-dimension and general array, function pointer, custom modifier, and typed reference forms; class and valuetype operands keep their encoded TypeDefOrRefOrSpec values, and unsupported forms such as vararg sentinels retain raw signature hashes.",
    ));
    if !selection.is_null() {
        out.push(Value::from(
            "Types, fields, methods, call edges, field accesses, and user strings cover only the selected declaring types; coverage describes that selection. Edge targets outside it keep their names but are not described.",
        ));
    }
    if unreadable_names != 0 {
        out.push(Value::from(format!(
            "{unreadable_names} TypeDef name(s) could not be read; a name in selection.unmatched_type_names may belong to one of them, so its absence is not observed."
        )));
    }
    Value::Array(out)
}

/// `unavailable(target, bytes, issue, typeNames)`.
fn unavailable(
    target: &Target<'_>,
    bytes: &[u8],
    issue: Option<&ManagedParseIssue>,
    type_names: Option<&[String]>,
) -> Value {
    let status = match issue {
        None => "absent",
        Some(issue) if issue.code == "resource-limit" => "partial",
        Some(_) => "malformed",
    };
    let mut map = Map::new();
    map.insert("signature_resolution".into(), Value::from("type-names-v1"));
    map.insert("artifact".into(), artifact_value(target, bytes));
    map.insert("module".into(), Value::Null);
    let mut metadata = Map::new();
    metadata.insert("status".into(), Value::from(status));
    metadata.insert("version".into(), Value::Null);
    metadata.insert("table_row_counts".into(), Value::Object(Map::new()));
    map.insert("metadata".into(), Value::Object(metadata));
    let mut identity = Map::new();
    identity.insert("token_identity".into(), Value::from("build-local"));
    identity.insert(
        "requires_artifact_sha256".into(),
        Value::from(target.sha256),
    );
    identity.insert("requires_mvid".into(), Value::Null);
    map.insert("identity_scope".into(), Value::Object(identity));
    map.insert("types".into(), Value::Array(Vec::new()));
    map.insert("nesting_read".into(), Value::from(false));
    map.insert("exported_types".into(), Value::Null);
    map.insert("fields".into(), Value::Array(Vec::new()));
    map.insert("methods".into(), Value::Array(Vec::new()));
    map.insert("member_refs".into(), Value::Array(Vec::new()));
    map.insert("call_edges".into(), Value::Array(Vec::new()));
    map.insert("field_accesses".into(), Value::Array(Vec::new()));
    map.insert("user_strings".into(), Value::Null);
    // Nothing was examined, so no requested name is known to be unmatched.
    let selection = match type_names {
        None => Value::Null,
        Some(names) => {
            let mut selection = Map::new();
            selection.insert(
                "type_names".into(),
                Value::Array(names.iter().map(|name| Value::from(name.clone())).collect()),
            );
            selection.insert("unmatched_type_names".into(), Value::Array(Vec::new()));
            Value::Object(selection)
        }
    };
    map.insert("selection".into(), selection);
    let mut coverage = Map::new();
    coverage.insert("state".into(), Value::from("unavailable"));
    coverage.insert(
        "issues".into(),
        Value::Array(match issue {
            None => Vec::new(),
            Some(issue) => vec![issue.to_value()],
        }),
    );
    map.insert("coverage".into(), Value::Object(coverage));
    map.insert(
        "limitations".into(),
        Value::Array(vec![Value::from(match issue {
            None => {
                "The PE has no admitted CLI metadata; managed member inspection is unavailable."
            }
            Some(_) => {
                "The CLI metadata could not be admitted; managed member inspection is unavailable."
            }
        })]),
    );
    Value::Object(map)
}
