//! Shared PE resource Evidence workflow over the common stable-file owner.
//! The input adapter chooses budgets; this application layer owns Evidence,
//! architecture attribution, and operation-specific failure projection.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use base64::Engine;
use rea_core::{
    cancellation::Cancellation,
    evidence::record::EvidenceRecord,
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
};
use rea_host::fs::stable_file::{ReadIssue, Snapshot};
use rea_rust_analysis::pe::resources::{self as pe_resources, Artifact, Error, Input, Report};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_pe_resources";
pub const MAX_CAPTURE_BYTES: usize = pe_resources::MAX_FILE_BYTES;
const PROVIDER: Provider = Provider {
    id: "pe-resource-reader",
    name: "REA PE resource reader",
    version: Some("1"),
};
const EXECUTION_MESSAGE: &str = "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";

#[derive(Clone, Copy)]
struct Budgets {
    max_file_bytes: usize,
    max_entries: usize,
}

#[derive(Default)]
pub struct PeResourcesAnalyzer;

impl ArtifactAnalyzer for PeResourcesAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = pe_resources::MAX_FILE_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(
            path,
            snapshot,
            Input {
                max_file_bytes: pe_resources::DEFAULT_FILE_BYTES,
                max_entries: pe_resources::DEFAULT_DIRECTORY_ENTRIES,
            },
            Budgets {
                max_file_bytes: pe_resources::DEFAULT_FILE_BYTES,
                max_entries: pe_resources::DEFAULT_DIRECTORY_ENTRIES,
            },
            &Cancellation::default(),
        )
    }
}

pub struct PeResourcesInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, PeResourcesAnalyzer>,
}

impl<F: rea_host::fs::stable_file::FileAccess> PeResourcesInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }

    pub fn with_records(
        access: Arc<F>,
        records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
    ) -> Self {
        Self {
            inner: ArtifactInspection::with_records(access, records),
        }
    }

    pub fn records(&self) -> &Arc<crate::ledger::artifact_records::ArtifactRecords> {
        self.inner.records()
    }

    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }

    pub fn inspect(
        &mut self,
        input: crate::inputs::PeResourcesInput,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        let parser_input = Input {
            max_file_bytes: input.max_file_bytes,
            max_entries: input.max_entries,
        };
        let budgets = Budgets {
            max_file_bytes: input.max_file_bytes,
            max_entries: input.max_entries,
        };
        self.inner.inspect_with_read_failure_projection(
            &input.path,
            input.max_file_bytes,
            cancellation,
            completion,
            move |path, snapshot, cancellation| {
                build_evidence(path, snapshot, parser_input, budgets, cancellation)
            },
            move |issue, path| project_read_issue(issue, path, budgets),
        )
    }
}

/// Parse a caller-supplied PE snapshot or project authenticated Evidence.
/// This boundary deliberately has no filesystem or provider authority.
pub fn inspect_captured(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_for(OPERATION, "invalid_input", "input must be an object".into()))?;
    validate_captured_fields(object)?;

    if let Some(evidence) = object.get("evidence") {
        return project_captured_evidence(evidence);
    }

    let path = required_text(object, "path")?;
    let encoded = required_text(object, "bytes_base64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            invalid_for(
                OPERATION,
                "invalid_input",
                format!("bytes_base64 is invalid: {error}"),
            )
        })?;
    if bytes.len() > MAX_CAPTURE_BYTES {
        return Err(invalid_for(
            OPERATION,
            "resource_constraint",
            "captured PE bytes exceed the input limit".into(),
        ));
    }
    let digest = hex_digest(&bytes);
    if let Some(declared) = object.get("sha256").and_then(Value::as_str)
        && !declared.eq_ignore_ascii_case(&digest)
    {
        return Err(invalid_for(
            OPERATION,
            "invalid_input",
            "sha256 does not match bytes_base64".into(),
        ));
    }

    let max_file_bytes = bounded_limit(
        object,
        "max_file_bytes",
        pe_resources::DEFAULT_FILE_BYTES,
        MAX_CAPTURE_BYTES,
    )?;
    let max_entries = bounded_limit(
        object,
        "max_entries",
        pe_resources::DEFAULT_DIRECTORY_ENTRIES,
        pe_resources::MAX_DIRECTORY_ENTRIES,
    )?;
    if bytes.len() > max_file_bytes {
        return Err(invalid_for(
            OPERATION,
            "resource_constraint",
            "captured PE bytes exceed max_file_bytes".into(),
        ));
    }
    let report = pe_resources::read(
        &bytes,
        Artifact {
            path: path.to_owned(),
            sha256: digest.clone(),
            bytes: bytes.len(),
        },
        Input {
            max_file_bytes,
            max_entries,
        },
        &Cancellation::default(),
    )
    .map_err(|error| {
        invalid_for(
            OPERATION,
            "invalid_format",
            format!("PE resource parsing failed: {error:?}"),
        )
    })?;
    validate_report(
        &report,
        Budgets {
            max_file_bytes,
            max_entries,
        },
    )?;
    let result = serde_json::to_value(report)
        .map_err(|error| invalid_for(OPERATION, "analysis_output", error.to_string()))?;
    Ok(json!({
        "subject": {"path": path, "sha256": digest, "format": "pe"},
        "result": result,
        "provenance": {"source": "caller-supplied-capture", "execution": "not-performed"}
    }))
}

fn validate_captured_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED: &[&str] = &[
        "path",
        "bytes_base64",
        "sha256",
        "max_file_bytes",
        "max_entries",
        "evidence",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(invalid_for(
            OPERATION,
            "invalid_input",
            format!("unexpected field: {field}"),
        ));
    }
    let has_evidence = object.contains_key("evidence");
    let has_bytes = object.contains_key("path") || object.contains_key("bytes_base64");
    if has_evidence && (has_bytes || object.len() != 1) {
        return Err(invalid_for(
            OPERATION,
            "invalid_input",
            "Evidence input must contain only evidence".into(),
        ));
    }
    if !has_evidence && !(object.contains_key("path") && object.contains_key("bytes_base64")) {
        return Err(invalid_for(
            OPERATION,
            "invalid_input",
            "byte input requires path and bytes_base64".into(),
        ));
    }
    Ok(())
}

fn project_captured_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid_for(OPERATION, "evidence_integrity", error.to_string()))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid_for(OPERATION, "evidence_integrity", error.to_string()))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid_for(
            OPERATION,
            "evidence_integrity",
            "Evidence operation does not match inspect_pe_resources".into(),
        ));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid_for(OPERATION, "evidence_integrity", error.to_string()))?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "subject": serde_json::from_str::<Value>(record.subject().get()).unwrap_or(Value::Null),
        "result": result,
        "source_evidence": serde_json::from_str::<Value>(record.raw().get()).unwrap_or(Value::Null),
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"}
    }))
}

fn required_text<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid_for(
                OPERATION,
                "invalid_input",
                format!("{field} must be a non-empty string"),
            )
        })?;
    if value.contains('\0') {
        return Err(invalid_for(
            OPERATION,
            "invalid_input",
            format!("{field} must not contain NUL bytes"),
        ));
    }
    Ok(value)
}

fn bounded_limit(
    object: &Map<String, Value>,
    field: &'static str,
    default: usize,
    maximum: usize,
) -> Result<usize, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(default);
    if value == 0 || value > maximum {
        return Err(invalid_for(
            OPERATION,
            "invalid_input",
            format!("{field} is outside its supported range"),
        ));
    }
    Ok(value)
}

fn hex_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn invalid_for(operation: &'static str, kind: &'static str, message: String) -> Failure {
    crate::artifacts::inspection::invalid_for(operation, kind, message)
}

#[derive(Serialize)]
struct Parameters {
    max_file_bytes: usize,
    max_entries: usize,
}

/// Recheck the producer's cross-field guarantees before exposing PE Evidence.
///
/// The TypeScript service performs this check after provider invocation. The
/// Rust parser normally establishes the same invariants while decoding, but
/// keeping the check at the application boundary protects Evidence consumers
/// if another reader or a future parser path supplies a `Report`.
fn validate_report(report: &Report, budgets: Budgets) -> Result<(), Failure> {
    let inside = |range: &rea_rust_analysis::pe::resources::Range| {
        range.offset <= report.artifact.bytes.saturating_sub(range.bytes)
    };

    let examined_entries = report
        .directories
        .iter()
        .map(|directory| usize::from(directory.named_entries) + usize::from(directory.id_entries))
        .sum::<usize>();
    let coverage_valid = report.artifact.bytes <= budgets.max_file_bytes
        && report.coverage.resources == report.resources.len()
        && report.coverage.examined_entries <= budgets.max_entries
        && report.coverage.examined_entries == examined_entries;
    if !coverage_valid {
        return Err(provider_output_failure(
            "PE resource provider returned inconsistent coverage or exceeded the selected budget.",
        ));
    }

    if report.directory.is_none()
        && (!report.directories.is_empty() || !report.resources.is_empty())
    {
        return Err(provider_output_failure(
            "PE resource provider returned resources without a resource directory.",
        ));
    }
    if let Some(directory) = &report.directory
        && (!inside(&directory.location) || !inside(&directory.data_directory_location))
    {
        return Err(provider_output_failure(
            "PE resource directory locations fall outside the captured artifact.",
        ));
    }

    if !report
        .directories
        .iter()
        .all(|directory| inside(&directory.location))
    {
        return Err(provider_output_failure(
            "PE resource directory ranges fall outside the captured artifact.",
        ));
    }
    if !report
        .resources
        .iter()
        .enumerate()
        .all(|(index, resource)| {
            resource.index == index
                && inside(&resource.data_entry_location)
                && inside(&resource.payload.location)
                && resource.entry_locations.iter().all(inside)
                && identity_location_is_inside(&resource.r#type, &inside)
                && identity_location_is_inside(&resource.name, &inside)
                && identity_location_is_inside(&resource.language, &inside)
        })
    {
        return Err(provider_output_failure(
            "PE resource provider returned malformed resource identity or location evidence.",
        ));
    }

    if report
        .icon_groups
        .iter()
        .any(|group| !valid_icon_group(report, group, &inside))
    {
        return Err(provider_output_failure(
            "PE resource provider returned malformed icon relationship evidence.",
        ));
    }

    Ok(())
}

fn valid_icon_group(
    report: &Report,
    group: &rea_rust_analysis::pe::resources::IconGroup,
    inside: &impl Fn(&rea_rust_analysis::pe::resources::Range) -> bool,
) -> bool {
    let Some(resource) = report.resources.get(group.resource_index) else {
        return false;
    };
    if !matches!(
        &resource.r#type,
        rea_rust_analysis::pe::resources::Identity::Id { id: 14 }
    ) {
        return false;
    }

    group.images.iter().all(|image| {
        let image_end = image.location.offset.saturating_add(image.location.bytes);
        let payload_end = resource
            .payload
            .location
            .offset
            .saturating_add(resource.payload.location.bytes);
        inside(&image.location)
            && image.location.offset >= resource.payload.location.offset
            && image_end <= payload_end
            && image.candidate_resource_indices.iter().all(|index| {
                report.resources.get(*index).is_some_and(|icon| {
                    matches!(
                        &icon.r#type,
                        rea_rust_analysis::pe::resources::Identity::Id { id: 3 }
                    ) && matches!(
                        &icon.name,
                        rea_rust_analysis::pe::resources::Identity::Id { id }
                            if *id == u32::from(image.resource_id)
                    )
                })
            })
            && valid_icon_resolution(report, resource, image)
    })
}

fn valid_icon_resolution(
    report: &Report,
    group_resource: &rea_rust_analysis::pe::resources::Resource,
    image: &rea_rust_analysis::pe::resources::IconImage,
) -> bool {
    let Some(index) = image.same_language_resource_index else {
        return image.size_matches.is_none();
    };
    image.candidate_resource_indices.contains(&index)
        && report.resources.get(index).is_some_and(|icon| {
            same_identity(&icon.language, &group_resource.language)
                && image.size_matches
                    == Some(icon.payload.location.bytes == image.declared_bytes as usize)
        })
}

fn identity_location_is_inside(
    identity: &rea_rust_analysis::pe::resources::Identity,
    inside: &impl Fn(&rea_rust_analysis::pe::resources::Range) -> bool,
) -> bool {
    match identity {
        rea_rust_analysis::pe::resources::Identity::Id { .. } => true,
        rea_rust_analysis::pe::resources::Identity::Name { location, .. } => inside(location),
    }
}

fn same_identity(
    left: &rea_rust_analysis::pe::resources::Identity,
    right: &rea_rust_analysis::pe::resources::Identity,
) -> bool {
    match (left, right) {
        (
            rea_rust_analysis::pe::resources::Identity::Id { id: left },
            rea_rust_analysis::pe::resources::Identity::Id { id: right },
        ) => left == right,
        (
            rea_rust_analysis::pe::resources::Identity::Name {
                utf16le_hex: left, ..
            },
            rea_rust_analysis::pe::resources::Identity::Name {
                utf16le_hex: right, ..
            },
        ) => left == right,
        _ => false,
    }
}

fn provider_output_failure(reason: &'static str) -> Failure {
    Failure::new_with_details(
        "analysis_output",
        "analysis_output",
        "PE resource provider returned malformed output.".into(),
        false,
        "Review the PE resource provider output and retry.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(OPERATION.into())),
            (String::from("reason"), Detail::Text(reason.into())),
        ]),
    )
}

fn build_evidence(
    path: &str,
    snapshot: Snapshot,
    input: Input,
    budgets: Budgets,
    cancellation: &Cancellation,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let report = pe_resources::read(
        &snapshot.bytes,
        Artifact {
            path: path.to_owned(),
            sha256: snapshot.sha256.clone(),
            bytes: snapshot.bytes.len(),
        },
        input,
        cancellation,
    )
    .map_err(|error| parse_failure(error, path, budgets))?;
    validate_report(&report, budgets)?;

    let architecture = subject_architecture(&report);
    let subject = Subject::new(path, snapshot.sha256, NativeFormat::Pe, architecture)
        .map_err(|error| execution(path, error.to_string()))?;
    let mut locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    append_source_locations(&mut locations, &report);
    let limitations = report.limitations.clone();
    let evidence = ArtifactEvidence::new_with_parameters(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations,
            locations,
        },
        Parameters {
            max_file_bytes: input.max_file_bytes,
            max_entries: input.max_entries,
        },
    )
    .map_err(|error| execution(path, error.to_string()))?;

    Ok(Arc::new(evidence))
}

fn append_source_locations(locations: &mut Vec<Location>, report: &Report) {
    if let Some(directory) = &report.directory {
        push_range_location(locations, &directory.location);
        push_range_location(locations, &directory.data_directory_location);
    }

    for directory in &report.directories {
        push_range_location(locations, &directory.location);
    }

    for resource in &report.resources {
        push_identity_location(locations, &resource.r#type);
        push_identity_location(locations, &resource.name);
        push_identity_location(locations, &resource.language);
        for entry in &resource.entry_locations {
            push_range_location(locations, entry);
        }
        push_range_location(locations, &resource.data_entry_location);
        push_range_location(locations, &resource.payload.location);
    }

    for group in &report.icon_groups {
        for image in &group.images {
            push_range_location(locations, &image.location);
            push_optional_range_location(locations, image.resolved_location.as_ref());
        }
    }
    for icon in &report.icons {
        push_range_location(locations, &icon.location);
    }
    for cursor in &report.cursors {
        push_range_location(locations, &cursor.location);
    }
    for group in &report.cursor_groups {
        for image in &group.images {
            push_range_location(locations, &image.location);
            push_optional_range_location(locations, image.resolved_location.as_ref());
        }
    }
    for bitmap in &report.bitmaps {
        push_range_location(locations, &bitmap.location);
        push_range_location(locations, &bitmap.header_location);
    }
    for font in &report.fonts {
        push_range_location(locations, &font.location);
        push_range_location(locations, &font.header_location);
        if let Some(font_name) = &font.font_name {
            push_identity_location(locations, font_name);
        }
        for entry in &font.entry_locations {
            push_range_location(locations, entry);
        }
    }
    push_optional_range_location(
        locations,
        report
            .version_info
            .as_ref()
            .map(|version| &version.location),
    );
    if let Some(version) = &report.version_info {
        for location in version.string_locations.values() {
            push_range_location(locations, location);
        }
    }
    for manifest in &report.manifests {
        push_range_location(locations, &manifest.location);
    }
    for html in &report.html {
        push_range_location(locations, &html.location);
    }
    for rcdata in &report.rcdata {
        push_range_location(locations, &rcdata.location);
    }
    for string in &report.strings {
        push_range_location(locations, &string.location);
        push_range_location(locations, &string.value_location);
    }
    for dialog in &report.dialogs {
        push_range_location(locations, &dialog.location);
        push_dialog_value_location(locations, &dialog.menu);
        push_dialog_value_location(locations, &dialog.class);
        push_dialog_value_location(locations, &dialog.title);
        for control in &dialog.controls {
            push_range_location(locations, &control.location);
            push_dialog_value_location(locations, &control.class);
            push_dialog_value_location(locations, &control.title);
        }
    }
    for menu in &report.menus {
        push_range_location(locations, &menu.location);
        for item in &menu.items {
            push_range_location(locations, &item.location);
            push_dialog_value_location(locations, &item.text);
        }
    }
    for accelerator in &report.accelerators {
        push_range_location(locations, &accelerator.location);
        for entry in &accelerator.entries {
            push_range_location(locations, &entry.location);
        }
    }
}

fn push_dialog_value_location(locations: &mut Vec<Location>, value: &pe_resources::DialogValue) {
    if let pe_resources::DialogValue::Text { location, .. } = value {
        push_range_location(locations, location);
    }
}

fn push_identity_location(locations: &mut Vec<Location>, identity: &pe_resources::Identity) {
    if let pe_resources::Identity::Name { location, .. } = identity {
        push_range_location(locations, location);
    }
}

fn push_optional_range_location(
    locations: &mut Vec<Location>,
    range: Option<&pe_resources::Range>,
) {
    if let Some(range) = range {
        push_range_location(locations, range);
    }
}

fn push_range_location(locations: &mut Vec<Location>, range: &pe_resources::Range) {
    if range.bytes == 0 {
        return;
    }

    locations.push(Location::FileOffsetRange {
        start: range.offset as u64,
        end: range.offset.saturating_add(range.bytes) as u64,
    });
}

fn subject_architecture(report: &Report) -> Option<Architecture> {
    let (architecture, expected_magic) = decoded_machine(report.machine)?;
    let required_format = if expected_magic == 0x20b {
        "pe32-plus"
    } else {
        "pe32"
    };
    (report.format == required_format).then_some(architecture)
}

/// Match the TypeScript provider's PE machine decoding, including the
/// ReadyToRun native-OS override values used for non-Windows managed images.
fn decoded_machine(machine: u32) -> Option<(Architecture, u16)> {
    direct_machine(machine).or_else(|| {
        NATIVE_OS_OVERRIDES
            .iter()
            .find_map(|override_value| direct_machine(machine ^ override_value))
    })
}

fn direct_machine(machine: u32) -> Option<(Architecture, u16)> {
    match machine {
        0x014c => Some((Architecture::X86, 0x10b)),
        0x8664 => Some((Architecture::X86_64, 0x20b)),
        0x01c0 | 0x01c2 | 0x01c4 => Some((Architecture::Arm, 0x10b)),
        0xaa64 => Some((Architecture::Arm64, 0x20b)),
        _ => None,
    }
}

const NATIVE_OS_OVERRIDES: [u32; 6] = [0x4644, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992];

fn parse_failure(error: Error, path: &str, budgets: Budgets) -> Failure {
    match error {
        Error::Malformed(reason) | Error::Unsupported(reason) => {
            crate::artifacts::inspection::invalid_for(OPERATION, "invalid_format", reason.into())
        }
        Error::ResourceLimit {
            boundary: "capacity",
            reason,
            ..
        } => resource_failure(
            "capacity",
            reason.to_owned(),
            budgets,
            false,
            input_budget_remediation("capacity", budgets),
        ),
        Error::ResourceLimit {
            boundary: "memory",
            reason,
            ..
        } => resource_failure(
            "memory",
            reason.to_owned(),
            budgets,
            false,
            "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits.".into(),
        ),
        Error::ResourceLimit { reason, .. } => resource_failure(
            "memory",
            reason.to_owned(),
            budgets,
            false,
            "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits.".into(),
        ),
        Error::Cancelled(reason) => cancelled(&reason),
        Error::Encoding(error) => execution(path, error.to_string()),
    }
}

fn resource_failure(
    kind: &'static str,
    reason: String,
    budgets: Budgets,
    retryable: bool,
    action: String,
) -> Failure {
    let mut details = details();
    details.insert("resource", text(kind));
    details.insert("reason", text(reason.clone()));
    let limits = BTreeMap::from([
        (
            "max_file_bytes",
            Detail::Count(budgets.max_file_bytes as u64),
        ),
        ("max_entries", Detail::Count(budgets.max_entries as u64)),
    ]);
    details.insert("reported_limits", Detail::Fields(limits));
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason,
        retryable,
        action,
        details,
    )
}

fn project_read_issue(issue: &ReadIssue, path: &str, budgets: Budgets) -> Failure {
    match issue {
        ReadIssue::Limit { maximum_bytes } => resource_failure(
            "file-size",
            format!("Selected artifact exceeds {maximum_bytes} bytes: {path}"),
            budgets,
            false,
            input_budget_remediation("file-size", budgets),
        ),
        issue => crate::artifacts::inspection::read_failure(OPERATION, PROVIDER, issue, path),
    }
}

fn input_budget_remediation(boundary: &'static str, budgets: Budgets) -> String {
    match boundary {
        "file-size" if budgets.max_file_bytes >= pe_resources::MAX_FILE_BYTES => format!(
            "The image exceeds the {}-byte input ceiling this operation accepts; select a smaller artifact.",
            pe_resources::MAX_FILE_BYTES
        ),
        "file-size" => format!(
            "Raise max_file_bytes above {} bytes or select a smaller artifact; the limit is the caller-selected input read budget.",
            budgets.max_file_bytes
        ),
        "capacity" if budgets.max_entries >= pe_resources::MAX_DIRECTORY_ENTRIES => format!(
            "The image exceeds the {}-entry resource-directory ceiling this operation accepts; select a smaller artifact.",
            pe_resources::MAX_DIRECTORY_ENTRIES
        ),
        "capacity" => format!(
            "Raise max_entries above {} or select a smaller artifact; the limit is the caller-selected resource directory entry budget.",
            budgets.max_entries
        ),
        _ => unreachable!("unknown PE input budget boundary"),
    }
}

fn cancelled(reason: &str) -> Failure {
    let mut details = details();
    details.insert("cleanup", text("complete"));
    details.insert("cancellation_reason", text(reason));
    let message = "Analysis was cancelled. Start it again when ready.";
    Failure::new(
        "cancelled",
        "cancelled",
        message.into(),
        true,
        message.into(),
        details,
    )
}

fn execution(path: &str, reason: String) -> Failure {
    let mut details = details();
    details.insert("provider_id", text(PROVIDER.id));
    details.insert(
        "diagnostics",
        Detail::Fields(BTreeMap::from([
            ("path", text(path)),
            ("reason", text(reason)),
        ])),
    );
    Failure::new(
        "execution_failure",
        "execution_failure",
        EXECUTION_MESSAGE.into(),
        false,
        EXECUTION_MESSAGE.into(),
        details,
    )
}

fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", text(OPERATION))])
}

fn text(value: impl Into<String>) -> Detail {
    Detail::Text(value.into())
}
