//! PE/CLI identity triage and classification from local bytes.
//!
//! Port of `src/dotnet/ManagedArtifactInspector.ts`. Returns exactly the JSON
//! object the TS `inspectManagedArtifactBytes` returns.

use serde_json::{Map, Value};

use super::Target;
use super::budget::admit_managed_projection;
use super::failure::{ManagedParseIssue, ReadError, ReadResult};
use super::inventory::{
    ManagedMetadataInventory, managed_table_row_counts, read_managed_metadata_inventory,
    read_managed_resource_directory,
};
use super::layout::{ManagedMetadataLayout, read_managed_metadata_layout};
use super::pe_reader::{
    ManagedCliHeader, ManagedPeLayout, managed_cli_32bit_requirement,
    managed_cli_is_mixed_clr_native, read_managed_pe_layout,
};
use super::type_member_lists::read_type_member_list_facts;

/// `flagNames(flags)`: the CLI header flag names in declaration order.
fn flag_names(flags: u32) -> Vec<String> {
    let mut names = Vec::new();
    for (mask, name) in [
        (0x0000_0001u32, "il-only"),
        (0x0000_0002, "32-bit-required"),
        (0x0000_0004, "il-library"),
        (0x0000_0008, "strong-name-signed"),
        (0x0000_0010, "native-entry-point"),
        (0x0001_0000, "track-debug-data"),
        (0x0002_0000, "32-bit-preferred"),
    ] {
        if (flags & mask) != 0 {
            names.push(name.to_string());
        }
    }
    names
}

/// `cliProjection(cli)`.
fn cli_projection(cli: &ManagedCliHeader) -> Value {
    let entry_point = if cli.entry_point == 0 {
        serde_json::json!({ "kind": "none", "value": Value::Null })
    } else if (cli.flags & 0x10) != 0 {
        serde_json::json!({
            "kind": "native-rva",
            "value": format!("0x{:x}", cli.entry_point),
        })
    } else {
        serde_json::json!({
            "kind": "metadata-token",
            "value": format!("0x{:08x}", cli.entry_point),
        })
    };
    serde_json::json!({
        "header_offset": cli.header_offset,
        "header_size": cli.header_size,
        "runtime_version": format!("{}.{}", cli.runtime_major, cli.runtime_minor),
        "flags": cli.flags,
        "flag_names": flag_names(cli.flags),
        "entry_point": entry_point,
        "metadata_rva": cli.metadata.rva,
        "metadata_size": cli.metadata.size,
        "resources_rva": cli.resources.rva,
        "resources_size": cli.resources.size,
        "strong_name_rva": cli.strong_name.rva,
        "strong_name_size": cli.strong_name.size,
        "managed_native_header_rva": cli.managed_native_header.rva,
        "managed_native_header_size": cli.managed_native_header.size,
        "ready_to_run_signature": cli.ready_to_run_signature,
    })
}

/// `peProjection(layout)`.
fn pe_projection(layout: &ManagedPeLayout) -> Value {
    serde_json::json!({
        "machine": layout.machine,
        "machine_hex": format!("0x{:04x}", layout.machine),
        "architecture": layout.architecture.as_str(),
        "optional_header": layout.optional_header,
        "section_count": layout.section_count,
        "characteristics": layout.characteristics,
        "cli": match layout.cli.as_ref() {
            None => Value::Null,
            Some(cli) => cli_projection(cli),
        },
    })
}

/// `base(target, bytes, layout)`.
fn base(target: &Target<'_>, bytes: &[u8], layout: &ManagedPeLayout) -> Value {
    serde_json::json!({
        "artifact": {
            "path": target.path,
            "sha256": target.sha256,
            "byte_length": bytes.len(),
            "format": "pe",
        },
        "pe": pe_projection(layout),
    })
}

/// Merge the `base` object's `artifact` and `pe` keys into a result map ahead of
/// the remaining keys so the final key order is base-first, matching the TS
/// `{ ...base(...), classification, metadata, ... }` spread.
fn with_base(base_value: Value, rest: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    if let Value::Object(base_map) = base_value {
        for (key, value) in base_map {
            map.insert(key, value);
        }
    }
    for (key, value) in rest {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

/// `unavailableResult(target, bytes, layout)`.
fn unavailable_result(
    target: &Target<'_>,
    bytes: &[u8],
    layout: &ManagedPeLayout,
) -> ReadResult<Value> {
    let malformed = layout.cli_directory_state != super::pe_reader::CliDirectoryState::Absent;
    let issues: Vec<ManagedParseIssue> = layout.cli_issue.iter().cloned().collect();
    let limitation = if malformed {
        "The PE declares a CLI directory, but its CLI header could not be admitted."
    } else {
        "The PE has no CLI data directory; managed metadata and CIL are unavailable."
    };
    let value = with_base(
        base(target, bytes, layout),
        vec![
            (
                "classification",
                serde_json::json!({
                    "status": if malformed { "malformed" } else { "not-managed" },
                    "container": "pe",
                    "runtime_family": "unknown",
                    "implementation": if malformed { "unknown" } else { "not-managed" },
                    "managed_architecture": "unknown",
                    "evidence": [
                        {
                            "code": if malformed { "cli-directory-malformed" } else { "cli-directory-absent" },
                            "detail": limitation,
                            "file_offset": match layout.cli_issue.as_ref().and_then(|issue| issue.offset) {
                                Some(offset) => Value::from(offset),
                                None => Value::Null,
                            },
                        }
                    ],
                }),
            ),
            (
                "metadata",
                serde_json::json!({
                    "status": if malformed { "malformed" } else { "absent" },
                    "version": Value::Null,
                    "stream_names": [],
                    "table_row_counts": Map::new(),
                }),
            ),
            ("module", Value::Null),
            ("assembly", Value::Null),
            ("target_frameworks", Value::Array(vec![])),
            ("references", Value::Array(vec![])),
            ("resources", Value::Array(vec![])),
            ("attributes", Value::Array(vec![])),
            (
                "coverage",
                serde_json::json!({
                    "state": if malformed { "partial" } else { "unavailable" },
                    "issues": issues.iter().map(ManagedParseIssue::to_value).collect::<Vec<_>>(),
                }),
            ),
            ("limitations", Value::Array(vec![Value::from(limitation)])),
        ],
    );
    admit_managed_projection(&value, None)?;
    Ok(value)
}

fn runtime_family_from_cli_header(cli: Option<&ManagedCliHeader>) -> &'static str {
    match cli {
        Some(cli) if cli.ready_to_run_signature => "modern-dotnet",
        Some(cli) if managed_cli_is_mixed_clr_native(cli) => "mixed-clr-native",
        _ => "unknown",
    }
}

/// `runtimeFamilyFor(cli, inventory, metadata, layout)`: runtime family plus the
/// evidence entries, built in the TS push order.
fn runtime_family_for(
    cli: &ManagedCliHeader,
    inventory: &ManagedMetadataInventory,
    metadata: &ManagedMetadataLayout,
    layout: &ManagedPeLayout,
    bytes: &[u8],
) -> ReadResult<(&'static str, Vec<Value>)> {
    let mut evidence: Vec<Value> = vec![serde_json::json!({
        "code": "cli-header-observed",
        "detail": "A file-backed PE CLI header and metadata root were admitted.",
        "file_offset": cli.header_offset,
    })];
    let frameworks = &inventory.target_frameworks;
    let has_unity = inventory
        .reference_names
        .iter()
        .any(|name| name == "UnityEngine" || name.starts_with("UnityEngine."));
    let mut runtime_family = "unknown";
    if runtime_family_from_cli_header(Some(cli)) == "mixed-clr-native" {
        runtime_family = "mixed-clr-native";
        evidence.push(serde_json::json!({
            "code": "cli-il-only-clear",
            "detail": "COMIMAGE_FLAGS_ILONLY is clear, so managed and native analysis must remain composed.",
            "file_offset": cli.header_offset + 16,
        }));
    } else if has_unity {
        runtime_family = "unity-mono";
        evidence.push(serde_json::json!({
            "code": "unity-reference-observed",
            "detail": "The admitted AssemblyRef table contains a UnityEngine reference.",
            "file_offset": option_offset(metadata.table(35).map(|t| t.offset)),
        }));
    } else if frameworks
        .iter()
        .any(|value| value.starts_with(".NETFramework,"))
    {
        runtime_family = "dotnet-framework";
        evidence.push(serde_json::json!({
            "code": "target-framework-observed",
            "detail": "An assembly-level TargetFrameworkAttribute names .NET Framework.",
            "file_offset": option_offset(metadata.table(12).map(|t| t.offset)),
        }));
    } else if frameworks
        .iter()
        .any(|value| value.starts_with(".NETCoreApp,"))
        || cli.ready_to_run_signature
    {
        runtime_family = "modern-dotnet";
        let file_offset = if cli.ready_to_run_signature {
            let offset = layout
                .rva_to_offset(
                    bytes,
                    cli.managed_native_header.rva,
                    4,
                    "cli.managed-native-header",
                )
                .map_err(ReadError::from)?;
            Value::from(offset)
        } else {
            option_offset(metadata.table(12).map(|t| t.offset))
        };
        evidence.push(serde_json::json!({
            "code": if cli.ready_to_run_signature { "ready-to-run-signature-observed" } else { "target-framework-observed" },
            "detail": if cli.ready_to_run_signature {
                "The managed native header has the ReadyToRun signature."
            } else {
                "An assembly-level TargetFrameworkAttribute names modern .NET."
            },
            "file_offset": file_offset,
        }));
    } else if frameworks
        .iter()
        .any(|value| value.starts_with(".NETStandard,"))
    {
        evidence.push(serde_json::json!({
            "code": "target-framework-observed",
            "detail": "An assembly-level TargetFrameworkAttribute names .NET Standard, an API specification that does not identify a runtime family.",
            "file_offset": option_offset(metadata.table(12).map(|t| t.offset)),
        }));
    }
    Ok((runtime_family, evidence))
}

fn option_offset(offset: Option<i64>) -> Value {
    match offset {
        Some(offset) => Value::from(offset),
        None => Value::Null,
    }
}

/// `implementationFor(cli, metadata)`.
fn implementation_for(cli: &ManagedCliHeader, metadata: &ManagedMetadataLayout) -> &'static str {
    if cli.ready_to_run_signature {
        return "cil-and-ready-to-run";
    }
    if (cli.flags & 1) == 0 {
        return "cpp-cli-mixed";
    }
    if metadata.row_counts.get(6).copied().unwrap_or(0) == 0 {
        "metadata-only"
    } else {
        "cil"
    }
}

/// `managedArchitectureFor(layout, cli)`.
fn managed_architecture_for(layout: &ManagedPeLayout, cli: &ManagedCliHeader) -> &'static str {
    if layout.architecture != super::pe_machine::PeArchitecture::X86 || (cli.flags & 1) == 0 {
        return layout.architecture.as_str();
    }
    match managed_cli_32bit_requirement(cli.flags) {
        "required" => "x86",
        "preferred" => "anycpu-prefer-32",
        _ => "anycpu",
    }
}

/// `runtimeClassification({ layout, metadata, inventory })`: the four
/// classification fields contributed when CLI metadata is present.
fn runtime_classification(
    layout: &ManagedPeLayout,
    metadata: &ManagedMetadataLayout,
    inventory: &ManagedMetadataInventory,
    bytes: &[u8],
) -> ReadResult<Vec<(&'static str, Value)>> {
    let cli = layout.cli.as_ref().ok_or_else(|| {
        ReadError::Internal(super::failure::InternalFailure(
            "Managed classification requires CLI".to_string(),
        ))
    })?;
    let (runtime_family, mut evidence) =
        runtime_family_for(cli, inventory, metadata, layout, bytes)?;
    let implementation = implementation_for(cli, metadata);
    let managed_architecture = managed_architecture_for(layout, cli);
    evidence.push(serde_json::json!({
        "code": "managed-architecture-derived",
        "detail": format!(
            "Managed architecture {managed_architecture} is derived from PE machine and CLI flags."
        ),
        "file_offset": cli.header_offset + 16,
    }));
    Ok(vec![
        ("runtime_family", Value::from(runtime_family)),
        ("implementation", Value::from(implementation)),
        ("managed_architecture", Value::from(managed_architecture)),
        ("evidence", Value::Array(evidence)),
    ])
}

/// `partialMetadataResult({ target, bytes, layout, issue })`.
fn partial_metadata_result(
    target: &Target<'_>,
    bytes: &[u8],
    layout: &ManagedPeLayout,
    issue: &ManagedParseIssue,
) -> Value {
    let resource_limit = issue.code == "resource-limit";
    with_base(
        base(target, bytes, layout),
        vec![
            (
                "classification",
                serde_json::json!({
                    "status": if resource_limit { "managed" } else { "malformed" },
                    "container": "pe",
                    "runtime_family": runtime_family_from_cli_header(layout.cli.as_ref()),
                    "implementation": "unknown",
                    "managed_architecture": "unknown",
                    "evidence": [
                        {
                            "code": "metadata-not-admitted",
                            "detail": issue.detail,
                            "file_offset": match issue.offset {
                                Some(offset) => Value::from(offset),
                                None => Value::Null,
                            },
                        }
                    ],
                }),
            ),
            (
                "metadata",
                serde_json::json!({
                    "status": if resource_limit { "partial" } else { "malformed" },
                    "version": Value::Null,
                    "stream_names": [],
                    "table_row_counts": Map::new(),
                }),
            ),
            ("module", Value::Null),
            ("assembly", Value::Null),
            ("target_frameworks", Value::Array(vec![])),
            ("references", Value::Array(vec![])),
            ("resources", Value::Array(vec![])),
            ("attributes", Value::Array(vec![])),
            (
                "coverage",
                serde_json::json!({
                    "state": "partial",
                    "issues": [issue.to_value()],
                }),
            ),
            (
                "limitations",
                Value::Array(vec![Value::from(if resource_limit {
                    "CLI metadata inspection stopped at its representation budget; omitted facts are unknown."
                } else {
                    "CLI metadata could not be read because the PE/CLI structure is malformed or unsupported."
                })]),
            ),
        ],
    )
}

/// `inspectManagedArtifactBytes(bytes, target)`.
pub fn inspect_managed_artifact_bytes(bytes: &[u8], target: &Target<'_>) -> ReadResult<Value> {
    let layout = read_managed_pe_layout(bytes)?;
    if layout.cli.is_none() {
        return unavailable_result(target, bytes, &layout);
    }
    let cli = layout.cli.clone().expect("cli present");

    // Resolve the metadata layout; a reader failure becomes a partial result.
    let metadata = {
        let attempt = (|| -> ReadResult<ManagedMetadataLayout> {
            let metadata_offset = layout
                .rva_to_offset(bytes, cli.metadata.rva, cli.metadata.size, "cli.metadata")
                .map_err(ReadError::from)?;
            read_managed_metadata_layout(bytes, metadata_offset, cli.metadata.size)
                .map_err(ReadError::from)
        })();
        match attempt {
            Ok(metadata) => metadata,
            Err(ReadError::Reader(failure)) => {
                let value = partial_metadata_result(target, bytes, &layout, &failure.issue);
                admit_managed_projection(&value, None)?;
                return Ok(value);
            }
            Err(internal @ ReadError::Internal(_)) => return Err(internal),
        }
    };
    let mut resource_issues: Vec<ManagedParseIssue> = Vec::new();
    // `readManagedResourceDirectory` runs outside the second try in the TS, so
    // the only failure it propagates (a resource-limit) escapes the whole
    // inspection rather than becoming a partial result.
    let resource_directory = read_managed_resource_directory(bytes, &layout, &mut resource_issues)?;

    let built = build_managed_result(
        bytes,
        target,
        &layout,
        &metadata,
        resource_directory,
        resource_issues,
    );
    match built {
        Ok(value) => Ok(value),
        Err(ReadError::Reader(failure)) => {
            let value = partial_metadata_result(target, bytes, &layout, &failure.issue);
            admit_managed_projection(&value, None)?;
            Ok(value)
        }
        Err(internal @ ReadError::Internal(_)) => Err(internal),
    }
}

/// The success branch of `inspectManagedArtifactBytes`, built against the shared
/// metadata budget.
fn build_managed_result(
    bytes: &[u8],
    target: &Target<'_>,
    layout: &ManagedPeLayout,
    metadata: &ManagedMetadataLayout,
    resource_directory: Option<super::inventory::ManagedResourceDirectory>,
    resource_issues: Vec<ManagedParseIssue>,
) -> ReadResult<Value> {
    let member_lists = read_type_member_list_facts(bytes, metadata).map_err(ReadError::from)?;
    let inventory =
        read_managed_metadata_inventory(bytes, metadata, resource_directory, &member_lists)?;
    // `[...resourceIssues, ...inventory.issues]`.
    let mut issues: Vec<ManagedParseIssue> = resource_issues;
    issues.extend(inventory.issues.iter().cloned());
    let mut limitations: Vec<Value> = Vec::new();
    if !issues.is_empty() {
        limitations.push(Value::from(
            "At least one metadata or resource item could not be read; coverage is partial.",
        ));
    }
    limitations.push(Value::from(
        "Static inspection did not load the assembly, resolve dependencies through a CLR, decompile C#, or execute target code.",
    ));
    let complete = issues.is_empty();
    let mut classification: Vec<(&'static str, Value)> = vec![
        ("status", Value::from("managed")),
        ("container", Value::from("pe")),
    ];
    classification.extend(runtime_classification(layout, metadata, &inventory, bytes)?);
    let classification = {
        let mut map = Map::new();
        for (key, value) in classification {
            map.insert(key.to_string(), value);
        }
        Value::Object(map)
    };
    let value = with_base(
        base(target, bytes, layout),
        vec![
            ("classification", classification),
            (
                "metadata",
                serde_json::json!({
                    "status": if complete { "complete" } else { "partial" },
                    "version": metadata.version,
                    "stream_names": metadata.stream_names,
                    "table_row_counts": managed_table_row_counts(metadata),
                }),
            ),
            ("module", inventory.module.clone().unwrap_or(Value::Null)),
            (
                "assembly",
                inventory.assembly.clone().unwrap_or(Value::Null),
            ),
            (
                "target_frameworks",
                Value::Array(
                    inventory
                        .target_frameworks
                        .iter()
                        .map(|value| Value::from(value.clone()))
                        .collect(),
                ),
            ),
            ("references", Value::Array(inventory.references.clone())),
            ("resources", Value::Array(inventory.resources.clone())),
            ("attributes", Value::Array(inventory.attributes.clone())),
            (
                "coverage",
                serde_json::json!({
                    "state": if complete { "complete" } else { "partial" },
                    "issues": issues.iter().map(ManagedParseIssue::to_value).collect::<Vec<_>>(),
                }),
            ),
            ("limitations", Value::Array(limitations)),
        ],
    );
    let mut budget = metadata.budget();
    admit_managed_projection(&value, Some(&mut budget))?;
    drop(budget);
    Ok(value)
}
