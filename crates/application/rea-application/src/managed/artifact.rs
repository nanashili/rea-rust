//! Shared managed artifact application workflow.
//!
//! The analyzer owns PE/CLI parsing and freezes its facts as artifact-bound
//! Evidence. Adapters can later bind this operation without reinterpreting the
//! metadata payload.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::managed;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_managed_artifact";
pub const MEMBERS_OPERATION: &str = "inspect_managed_members";
pub const NATIVE_BOUNDARIES_OPERATION: &str = "inspect_managed_native_boundaries";
const PROVIDER: Provider = Provider {
    id: "rust-managed-static",
    name: "REA Rust managed metadata reader",
    version: Some("1"),
};
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Parse a caller-supplied managed artifact snapshot without acquiring a file.
/// The returned report keeps the source path and digest alongside the parser's
/// complete metadata facts so callers cannot accidentally detach build-local
/// tokens from their artifact identity.
pub fn inspect_captured(path: &str, bytes: &[u8]) -> Result<serde_json::Value, Failure> {
    if path.is_empty() || path.contains('\0') {
        return Err(execution(
            path,
            "path must be a non-empty NUL-free string".into(),
        ));
    }
    if bytes.len() > managed::MAX_INPUT_BYTES {
        return Err(resource_memory(
            path,
            "managed artifact exceeds the input limit",
        ));
    }

    let parsed = managed::inspect(bytes).map_err(|error| parse_failure(path, error))?;
    let report = Report {
        path: path.to_owned(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        inspection: parsed,
    };
    serde_json::to_value(report).map_err(|error| execution(path, error.to_string()))
}

#[derive(Default)]
pub struct ManagedArtifactAnalyzer;

impl ArtifactAnalyzer for ManagedArtifactAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = managed::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

pub struct ManagedArtifactInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, ManagedArtifactAnalyzer>,
}

/// Projects a completed managed-artifact parse for the member operation.
/// Selection is delegated to the analysis owner so tokens and parsed facts
/// retain their original artifact-bound identity.
pub fn inspect_managed_members<'a>(
    inspection: &'a managed::Inspection,
    type_names: Option<&[String]>,
) -> managed::ManagedMembersInspection<'a> {
    managed::inspect_managed_members(inspection, type_names)
}

#[derive(Debug, Serialize)]
pub struct ManagedMemberEvidence<'a> {
    pub path: String,
    pub sha256: String,
    pub members: managed::ManagedMembersInspection<'a>,
}

/// Builds the application-owned member projection while retaining the
/// artifact identity alongside every build-local member token.
pub fn project_member_evidence<'a>(
    path: &str,
    sha256: &str,
    inspection: &'a managed::Inspection,
    type_names: Option<&[String]>,
) -> ManagedMemberEvidence<'a> {
    ManagedMemberEvidence {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        members: inspect_managed_members(inspection, type_names),
    }
}

impl<F: rea_host::fs::stable_file::FileAccess> ManagedArtifactInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }
    pub fn inspect(
        &mut self,
        path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }

    pub fn inspect_members(
        &mut self,
        path: &str,
        type_names: Option<Vec<String>>,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with(
            path,
            managed::MAX_INPUT_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| build_member_evidence(path, snapshot, type_names.as_deref()),
        )
    }

    pub fn inspect_native_boundaries(
        &mut self,
        path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with(
            path,
            managed::MAX_INPUT_BYTES,
            cancellation,
            completion,
            |path, snapshot, _| build_native_boundary_evidence(path, snapshot),
        )
    }
}

fn build_native_boundary_evidence(
    path: &str,
    snapshot: Snapshot,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let parsed = managed::inspect(&snapshot.bytes).map_err(|error| parse_failure(path, error))?;
    let architecture = match parsed.pe.architecture {
        "x86" => Some(Architecture::X86),
        "x86_64" => Some(Architecture::X86_64),
        "arm" => Some(Architecture::Arm),
        "arm64" => Some(Architecture::Arm64),
        _ => None,
    };
    let subject = Subject::new(
        path,
        snapshot.sha256.clone(),
        NativeFormat::Pe,
        architecture,
    )
    .map_err(|error| execution(path, error.to_string()))?;
    let report = native_boundary_report(path, &snapshot.sha256, &parsed);
    if let Err(error) = json_output::admitted_length(&report, MAX_OUTPUT_BYTES) {
        return Err(resource(path, error));
    }
    drop(snapshot.bytes);
    Ok(Arc::new(
        ArtifactEvidence::new(
            subject,
            PROVIDER,
            Observation {
                operation: NATIVE_BOUNDARIES_OPERATION,
                result: report,
                limitations: vec![
                    "P/Invoke rows prove managed import declarations only; native libraries, exports, thunks, and addresses are not verified.".into(),
                    "Managed metadata tokens are build-local and require the reported artifact SHA-256 and MVID.".into(),
                    "This read-only inspection does not load or execute managed or native code.".into(),
                ],
                locations: vec![Location::ArtifactPath {
                    path: path.to_owned(),
                }],
            },
        )
        .map_err(|error| execution(path, error.to_string()))?,
    ))
}

fn native_boundary_report(
    path: &str,
    sha256: &str,
    parsed: &managed::Inspection,
) -> serde_json::Value {
    let module_refs = parsed
        .module_references
        .iter()
        .map(|module| {
            serde_json::json!({
                "token": module.token,
                "row_offset": module.source_offset,
                "name": module.name,
            })
        })
        .collect::<Vec<_>>();
    let pinvoke_imports = parsed
        .impl_maps
        .iter()
        .map(|mapping| {
            let flags = mapping.flags.unwrap_or_default();
            serde_json::json!({
                "token": mapping.token,
                "row_offset": mapping.source_offset,
                "mapping_flags": flags,
                "mapping_flags_hex": format!("0x{flags:04x}"),
                "member_token": mapping.member_token,
                "member_kind": mapping
                    .member_token
                    .as_deref()
                    .map(|token| managed_member_kind(parsed, token))
                    .unwrap_or("unknown"),
                "member_name": mapping.member_token.as_deref().and_then(|token| {
                    managed_method_name(parsed, token)
                        .or_else(|| managed_field_name(parsed, token))
                }),
                "import_name": mapping.import_name,
                "import_scope_token": mapping.module_token,
                "import_scope_name": mapping
                    .module_token
                    .as_deref()
                    .and_then(|token| managed_module_name(parsed, token)),
                "no_mangle": flags & 0x0001 != 0,
                "char_set": pinvoke_char_set(flags),
                "call_convention": pinvoke_call_convention(flags),
                "supports_last_error": flags & 0x0040 != 0,
                "best_fit": pinvoke_best_fit(flags),
                "throw_on_unmappable_char": pinvoke_throw_on_unmappable(flags),
                "verification": "managed-declaration-only",
            })
        })
        .collect::<Vec<_>>();
    let native_implementations = parsed
        .methods
        .iter()
        .filter_map(|method| {
            let pinvoke_declared = method.pinvoke_module_token.is_some()
                || method.pinvoke_import_name.is_some()
                || method.flags & 0x2000 != 0;
            let code_type = method.impl_code_type;
            let managed_kind = method.impl_managed_status;
            if !pinvoke_declared && code_type == "il" && managed_kind == "managed" {
                return None;
            }
            let boundary_kind = if pinvoke_declared {
                "pinvoke"
            } else if code_type == "native" {
                "native-body"
            } else if code_type == "runtime" {
                "runtime-provided"
            } else if managed_kind == "unmanaged" {
                "unmanaged-method"
            } else {
                "mixed-or-unknown"
            };
            Some(serde_json::json!({
                "token": method.token,
                "row_offset": method.source_offset,
                "name": method.name,
                "rva": method.rva,
                "flags": method.flags,
                "impl_flags": method.impl_flags,
                "impl_flag_names": method.impl_flag_names,
                "impl_unknown_flags": method.impl_unknown_flags,
                "impl_map_token": method.impl_map_token,
                "pinvoke_module_token": method.pinvoke_module_token,
                "pinvoke_import_name": method.pinvoke_import_name,
                "pinvoke_flags": method.pinvoke_flags,
                "code_type": code_type,
                "managed_kind": managed_kind,
                "pinvoke_declared": pinvoke_declared,
                "boundary_kind": boundary_kind,
                "body_interpretation": if code_type == "il" && managed_kind == "managed" && !pinvoke_declared { "managed-cil" } else if method.rva == 0 { "not-file-backed" } else { "native-or-runtime" },
            }))
        })
        .collect::<Vec<_>>();
    let cli_native = parsed.pe.cli.as_ref().map(|cli| {
        serde_json::json!({
            "il_only": cli.flags & 1 != 0,
            "requires_32bit": cli.flags & 2 != 0,
            "strong_name_signed": cli.flags & 8 != 0,
            "native_entry_point": cli.flags & 16 != 0,
            "ready_to_run_signature": serde_json::Value::Null,
            "managed_native_header_rva": serde_json::Value::Null,
            "managed_native_header_size": serde_json::Value::Null,
        })
    });
    serde_json::json!({
        "path": path,
        "sha256": sha256,
        "artifact": parsed.artifact,
        "module": parsed.module,
        "metadata": parsed.metadata,
        "identity_scope": {
            "token_identity": "build-local",
            "requires_artifact_sha256": sha256,
            "requires_mvid": parsed.module.as_ref().and_then(|module| module.mvid.as_deref()),
        },
        "cli_native": cli_native,
        "module_refs": module_refs,
        "pinvoke_imports": pinvoke_imports,
        "native_implementations": native_implementations,
        "summary": {
            "module_ref_count": parsed.module_references.len(),
            "pinvoke_import_count": parsed.impl_maps.len(),
            "native_implementation_count": parsed.methods.iter().filter(|method| method.pinvoke_module_token.is_some() || method.pinvoke_import_name.is_some() || method.flags & 0x2000 != 0 || method.impl_flags & 0x0003 != 0 || method.impl_flags & 0x0004 != 0).count(),
            "ready_to_run": serde_json::Value::Null,
            "mixed_mode_or_native_header": cli_native.as_ref().map(|value| value["native_entry_point"].as_bool().unwrap_or(false)),
        },
        "coverage": { "state": "complete", "issues": [] },
        "limitations": parsed.limitations,
    })
}

fn managed_method_name(parsed: &managed::Inspection, token: &str) -> Option<String> {
    parsed
        .methods
        .iter()
        .find(|method| method.token == token)
        .map(|method| method.name.clone())
}

fn managed_field_name(parsed: &managed::Inspection, token: &str) -> Option<String> {
    parsed
        .fields
        .iter()
        .find(|field| field.token == token)
        .map(|field| field.name.clone())
}

fn managed_member_kind(parsed: &managed::Inspection, token: &str) -> &'static str {
    if parsed.methods.iter().any(|method| method.token == token) {
        "method"
    } else if parsed.fields.iter().any(|field| field.token == token) {
        "field"
    } else {
        "unknown"
    }
}

fn pinvoke_char_set(flags: u16) -> &'static str {
    match flags & 0x0006 {
        0x0000 => "not-specified",
        0x0002 => "ansi",
        0x0004 => "unicode",
        0x0006 => "auto",
        _ => "unknown",
    }
}

fn pinvoke_call_convention(flags: u16) -> &'static str {
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

fn pinvoke_best_fit(flags: u16) -> &'static str {
    match flags & 0x0030 {
        0x0000 => "assembly-default",
        0x0010 => "enabled",
        0x0020 => "disabled",
        _ => "unknown",
    }
}

fn pinvoke_throw_on_unmappable(flags: u16) -> &'static str {
    match flags & 0x3000 {
        0x0000 => "assembly-default",
        0x1000 => "enabled",
        0x2000 => "disabled",
        _ => "unknown",
    }
}

fn managed_module_name(parsed: &managed::Inspection, token: &str) -> Option<String> {
    parsed
        .module_references
        .iter()
        .find(|module| module.token == token)
        .map(|module| module.name.clone())
}

#[derive(Debug, Serialize)]
struct Report {
    path: String,
    sha256: String,
    #[serde(flatten)]
    inspection: managed::Inspection,
}

fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let parsed = managed::inspect(&snapshot.bytes).map_err(|error| parse_failure(path, error))?;
    let architecture = match parsed.pe.architecture {
        "x86" => Some(Architecture::X86),
        "x86_64" => Some(Architecture::X86_64),
        "arm" => Some(Architecture::Arm),
        "arm64" => Some(Architecture::Arm64),
        _ => None,
    };
    let subject = Subject::new(
        path,
        snapshot.sha256.clone(),
        NativeFormat::Pe,
        architecture,
    )
    .map_err(|error| execution(path, error.to_string()))?;
    let locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    let report = Report {
        path: path.to_owned(),
        sha256: snapshot.sha256,
        inspection: parsed,
    };
    if let Err(error) = json_output::admitted_length(&report, MAX_OUTPUT_BYTES) {
        return Err(resource(path, error));
    }
    drop(snapshot.bytes);
    Ok(Arc::new(
        ArtifactEvidence::new(
            subject,
            PROVIDER,
            Observation {
                operation: OPERATION,
                result: report,
                limitations: vec![
                    "Managed metadata is read-only and does not execute CIL or native code.".into(),
                ],
                locations,
            },
        )
        .map_err(|error| execution(path, error.to_string()))?,
    ))
}

fn build_member_evidence(
    path: &str,
    snapshot: Snapshot,
    type_names: Option<&[String]>,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let parsed = managed::inspect(&snapshot.bytes).map_err(|error| parse_failure(path, error))?;
    let architecture = match parsed.pe.architecture {
        "x86" => Some(Architecture::X86),
        "x86_64" => Some(Architecture::X86_64),
        "arm" => Some(Architecture::Arm),
        "arm64" => Some(Architecture::Arm64),
        _ => None,
    };
    let subject = Subject::new(
        path,
        snapshot.sha256.clone(),
        NativeFormat::Pe,
        architecture,
    )
    .map_err(|error| execution(path, error.to_string()))?;
    let report = project_member_evidence(path, &snapshot.sha256, &parsed, type_names);
    let mut locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    locations.extend(report.members.params.iter().filter_map(|parameter| {
        parameter
            .source_offset
            .map(|offset| Location::FileOffsetRange {
                start: offset as u64,
                end: (offset as u64).saturating_add(1),
            })
    }));
    if let Err(error) = json_output::admitted_length(&report, MAX_OUTPUT_BYTES) {
        return Err(resource(path, error));
    }
    drop(snapshot.bytes);
    Ok(Arc::new(
        ArtifactEvidence::new_with_parameters(
            subject,
            PROVIDER,
            Observation {
                operation: MEMBERS_OPERATION,
                result: report,
                limitations: vec![
                    "Managed metadata is read-only and does not execute CIL or native code.".into(),
                    "Member tokens and references are build-local to the retained artifact digest."
                        .into(),
                ],
                locations,
            },
            serde_json::json!({ "type_names": type_names }),
        )
        .map_err(|error| execution(path, error.to_string()))?,
    ))
}

fn parse_failure(path: &str, error: managed::Error) -> Failure {
    match error {
        managed::Error::ResourceLimit(reason) => resource_memory(path, reason),
        managed::Error::Unsupported(reason) => {
            let mut fields = details();
            fields.insert("path", Detail::Text(path.to_owned()));
            fields.insert("reason", Detail::Text(reason.into()));
            Failure::new(
                "unsupported_target",
                "unsupported_target",
                format!("Unsupported target for {OPERATION} at {path}: {reason}"),
                false,
                "Select a PE target containing supported CLI metadata.".into(),
                fields,
            )
        }
        managed::Error::Malformed(reason) => crate::artifacts::inspection::invalid_for(
            OPERATION,
            "invalid_format",
            format!("Selected artifact {path}: {reason}"),
        ),
    }
}
fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("provider_id", Detail::Text(PROVIDER.id.into())),
    ])
}
fn execution(path: &str, reason: String) -> Failure {
    let mut fields = details();
    fields.insert("path", Detail::Text(path.into()));
    fields.insert("reason", Detail::Text(reason));
    Failure::new(
        "execution_failure",
        "execution_failure",
        "Managed analysis could not complete.".into(),
        false,
        "Review the reported diagnostics before retrying.".into(),
        fields,
    )
}
fn resource_memory(path: &str, reason: &str) -> Failure {
    let mut fields = details();
    fields.insert("resource", Detail::Text("memory".into()));
    fields.insert("reason", Detail::Text(reason.into()));
    fields.insert(
        "reported_limits",
        Detail::Fields(BTreeMap::from([(
            "maximum_bytes",
            Detail::Count(managed::MAX_INPUT_BYTES as u64),
        )])),
    );
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        format!("Selected artifact {path}: {reason}"),
        false,
        "Review the reported managed-reader memory limit or select a smaller artifact.".into(),
        fields,
    )
}
fn resource(path: &str, error: json_output::Error) -> Failure {
    resource_memory(path, &error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_pe_bytes_as_invalid_format() {
        let error = managed::inspect(b"not a PE").expect_err("invalid input");
        assert!(matches!(error, managed::Error::Malformed(_)));
    }
}
