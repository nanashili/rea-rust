pub use crate::artifacts::inspection::Completion;
use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection};
use rea_core::{
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::{auditable, image};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_rust_binary";
const PROVIDER: Provider = Provider {
    id: "rust-auditable",
    name: "REA Rust dependency reader",
    version: Some("1"),
};
const EXECUTION_MESSAGE: &str = "Analysis could not complete. Run `rea doctor` and review the reported details; repeating the unchanged request is not expected to succeed.";

#[derive(Default)]
pub struct RustBinaryAnalyzer;

impl ArtifactAnalyzer for RustBinaryAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = image::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

pub struct RustInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, RustBinaryAnalyzer>,
}

impl<F: rea_host::fs::stable_file::FileAccess> RustInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
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
        path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }
}

#[derive(Debug, Serialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub artifact: Artifact,
    #[serde(flatten)]
    pub image: image::Image,
    pub limitations: Vec<String>,
}

/// Parse a caller-supplied Rust binary snapshot without opening a path.
///
/// This boundary is used by the captured-only runtime adapter.  The regular
/// `RustInspection` workflow remains responsible for stable-file reads and
/// Evidence-session ownership; this helper only interprets bytes already
/// supplied by the caller and returns the same public report shape.
pub fn inspect_captured(path: &str, bytes: &[u8]) -> Result<Value, Failure> {
    if path.is_empty() || path.contains('\0') {
        return Err(invalid(
            "invalid_path",
            "Captured Rust binary path must be non-empty and NUL-free.".into(),
        ));
    }
    if bytes.len() > image::MAX_INPUT_BYTES {
        return Err(resource(
            "input",
            "Captured Rust binary exceeds the input limit.".into(),
            "maximum_input_bytes",
            image::MAX_INPUT_BYTES,
        ));
    }

    let parsed = image::read(bytes).map_err(|error| image_failure(error, path))?;
    let format = match parsed.format {
        image::Format::Elf => NativeFormat::Elf,
        image::Format::Pe => NativeFormat::Pe,
        image::Format::Macho => NativeFormat::MachO,
    };
    let report = Report {
        artifact: Artifact {
            path: path.to_owned(),
            sha256: rea_rust_analysis::managed::digest(bytes),
            bytes: bytes.len(),
        },
        limitations: limitations(&parsed),
        image: parsed,
    };
    validate_report(path, bytes.len(), &report)?;
    admit_report_length(path, &report)?;

    let _subject = Subject::new(
        path,
        report.artifact.sha256.clone(),
        format,
        architecture_for(&report.image.architecture),
    )
    .map_err(|error| execution(path, error.to_string()))?;
    serde_json::to_value(report).map_err(|error| execution(path, error.to_string()))
}

fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let parsed = image::read(&snapshot.bytes).map_err(|error| image_failure(error, path))?;
    let format = match parsed.format {
        image::Format::Elf => NativeFormat::Elf,
        image::Format::Pe => NativeFormat::Pe,
        image::Format::Macho => NativeFormat::MachO,
    };
    let architecture = architecture_for(&parsed.architecture);
    let locations = locations_for(path, &parsed)?;

    let limitations = limitations(&parsed);
    let subject = Subject::new(path, snapshot.sha256.clone(), format, architecture)
        .map_err(|error| execution(path, error.to_string()))?;
    let result = Report {
        artifact: Artifact {
            path: path.to_owned(),
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.len(),
        },
        image: parsed,
        limitations: limitations.clone(),
    };
    validate_report(path, result.artifact.bytes, &result)?;
    drop(snapshot.bytes);
    admit_report_length(path, &result)?;
    let evidence = Arc::new(
        ArtifactEvidence::new(
            subject,
            PROVIDER,
            Observation {
                operation: OPERATION,
                result,
                limitations,
                locations,
            },
        )
        .map_err(|error| execution(path, error.to_string()))?,
    );
    Ok(evidence)
}

fn architecture_for(architecture: &str) -> Option<Architecture> {
    match architecture {
        "386" => Some(Architecture::X86),
        "amd64" => Some(Architecture::X86_64),
        "arm" => Some(Architecture::Arm),
        "arm64" => Some(Architecture::Arm64),
        "mips" => Some(Architecture::Mips),
        "riscv" => Some(Architecture::Riscv),
        "powerpc" => Some(Architecture::Powerpc),
        "hexagon" => Some(Architecture::Hexagon),
        _ => None,
    }
}

fn locations_for(path: &str, parsed: &image::Image) -> Result<Vec<Location>, Failure> {
    let mut locations = vec![Location::ArtifactPath {
        path: path.to_owned(),
    }];
    let Some(section) = &parsed.auditable_metadata else {
        return Ok(locations);
    };
    let Some(end) = section
        .file_offset
        .checked_add(section.section_bytes as u64)
    else {
        return Err(execution(
            path,
            "Dependency section range overflowed.".into(),
        ));
    };

    locations.push(Location::FileOffsetRange {
        start: section.file_offset,
        end,
    });
    Ok(locations)
}

fn admit_report_length(path: &str, report: &Report) -> Result<(), Failure> {
    match json_output::admitted_length(report, auditable::MAX_OUTPUT_BYTES) {
        Ok(_) => Ok(()),
        Err(json_output::Error::Limit { maximum }) => Err(resource(
            "transport",
            format!(
                "Complete Rust metadata for {path} exceeds the inline output budget; no partial success is returned."
            ),
            "maximum_output_bytes",
            maximum,
        )),
        Err(json_output::Error::Encoding(error)) => Err(execution(path, error.to_string())),
    }
}

fn validate_report(path: &str, artifact_bytes: usize, report: &Report) -> Result<(), Failure> {
    if let Some(metadata) = &report.image.auditable_metadata {
        let offset = usize::try_from(metadata.file_offset).map_err(|_| {
            execution(
                path,
                "Dependency section offset exceeds the artifact range.".into(),
            )
        })?;
        let end = offset
            .checked_add(metadata.section_bytes)
            .ok_or_else(|| execution(path, "Dependency section range overflowed.".into()))?;
        if end > artifact_bytes || metadata.compressed_bytes != metadata.section_bytes {
            return Err(execution(
                path,
                "Dependency section range or compressed size is inconsistent.".into(),
            ));
        }

        validate_metadata_graph(path, metadata)?;
    }

    if let Some(commit) = &report.image.rustc_commit {
        if commit.hashes.is_empty()
            || commit.hashes.iter().any(|hash| {
                hash.hash.len() != 40
                    || !hash
                        .hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || hash.file_offset >= artifact_bytes
            })
        {
            return Err(execution(
                path,
                "Inferred rustc commit observations are inconsistent.".into(),
            ));
        }
    }
    Ok(())
}

fn validate_metadata_graph(path: &str, metadata: &auditable::Metadata) -> Result<(), Failure> {
    let package_count = metadata.packages.len();
    let mut roots = Vec::new();
    let mut expected_edges = Vec::new();
    for (from_index, package) in metadata.packages.iter().enumerate() {
        if package.root {
            roots.push(from_index);
        }
        for &to_index in &package.dependencies {
            if to_index >= package_count {
                return Err(execution(
                    path,
                    "Dependency index is outside the package list.".into(),
                ));
            }
            expected_edges.push((from_index, to_index));
        }
    }

    let actual_edges = metadata
        .dependency_edges
        .iter()
        .map(|edge| (edge.from_index, edge.to_index))
        .collect::<Vec<_>>();
    if actual_edges != expected_edges {
        return Err(execution(
            path,
            "Dependency edges do not match package dependencies.".into(),
        ));
    }

    let expected_root = match roots.as_slice() {
        [] => None,
        [root] => Some(*root),
        _ => {
            return Err(execution(
                path,
                "Dependency metadata declares more than one root package.".into(),
            ));
        }
    };
    if metadata.root_package_index != expected_root {
        return Err(execution(
            path,
            "Root package index does not match package roots.".into(),
        ));
    }
    if metadata.cyclic_dependency_indices != auditable_cycles(metadata) {
        return Err(execution(
            path,
            "Cyclic dependency indices do not match package dependencies.".into(),
        ));
    }
    Ok(())
}

fn auditable_cycles(metadata: &auditable::Metadata) -> Vec<usize> {
    let mut seen = vec![false; metadata.packages.len()];
    let mut order = Vec::with_capacity(metadata.packages.len());
    let mut stack = Vec::new();
    for start in 0..metadata.packages.len() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        stack.push((start, 0));
        while let Some((index, edge)) = stack.last_mut() {
            if let Some(&next) = metadata.packages[*index].dependencies.get(*edge) {
                *edge += 1;
                if !seen[next] {
                    seen[next] = true;
                    stack.push((next, 0));
                }
            } else {
                order.push(*index);
                stack.pop();
            }
        }
    }

    let mut reversed = vec![Vec::new(); metadata.packages.len()];
    for (from, package) in metadata.packages.iter().enumerate() {
        for &to in &package.dependencies {
            reversed[to].push(from);
        }
    }
    seen.fill(false);
    let mut cyclic = vec![false; metadata.packages.len()];
    let mut pending = Vec::new();
    for start in order.into_iter().rev() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        pending.push(start);
        let mut component = Vec::new();
        while let Some(index) = pending.pop() {
            component.push(index);
            for &next in &reversed[index] {
                if !seen[next] {
                    seen[next] = true;
                    pending.push(next);
                }
            }
        }
        if component.len() > 1
            || metadata.packages[component[0]]
                .dependencies
                .contains(&component[0])
        {
            for index in component {
                cyclic[index] = true;
            }
        }
    }
    cyclic
        .into_iter()
        .enumerate()
        .filter_map(|(index, value)| value.then_some(index))
        .collect()
}

fn limitations(image: &image::Image) -> Vec<String> {
    let mut values = vec![
        "Embedded dependency metadata is file content. It does not authenticate package names, versions, sources, or the compiler that produced the binary.".into(),
        "Only the .dep-v0 dependency section and read-only compiler path strings are inspected. Functions, types, and runtime behavior are not recovered.".into(),
        "Resource guards bound the selected file to 256 MiB, a dependency section to 1 MiB, inflated JSON to the smaller of 8 MiB and 64 times the section size, and the complete report to 8 MiB. Package and dependency counts are admitted against that output budget before schema cloning, graph objects, or reverse-edge allocation.".into(),
    ];

    append_metadata_limitations(&mut values, image);
    values.push(rustc_limitation(image).into());
    values
}

fn append_metadata_limitations(values: &mut Vec<String>, image: &image::Image) {
    let Some(metadata) = &image.auditable_metadata else {
        values.push(
            "No .dep-v0 section was found. Absence of .dep-v0 does not mean the binary has no dependencies."
                .into(),
        );
        return;
    };

    if let Some(version) = metadata.format_version
        && ![0, 1, 8].contains(&version)
    {
        values.push(unknown_format_limitation(version));
    }
    if metadata
        .packages
        .iter()
        .any(|package| package.kind.is_none())
    {
        values.push(
            "An omitted package kind is left null. The embedded format treats an omitted kind as runtime, and that default was not stored in the section."
                .into(),
        );
    }
    if !metadata.cyclic_dependency_indices.is_empty() {
        values.push(
            "Dependency indices contain a cycle. The cycle is reported and was not traversed."
                .into(),
        );
    }
}

fn unknown_format_limitation(version: u32) -> String {
    let preceding = [0, 1, 8]
        .into_iter()
        .filter(|known| *known < version)
        .max()
        .unwrap_or(0);

    format!(
        "cargo-auditable format revision {version} is unknown. Its schema directs readers to interpret it using the highest known preceding revision ({preceding}); this specific revision has not been independently verified."
    )
}

fn rustc_limitation(image: &image::Image) -> &'static str {
    match &image.rustc_commit {
        None => {
            "No /rustc/<40-hex>/ path was found in read-only data, so a rustc commit hash is unknown."
        }
        Some(commit) if commit.hashes.len() == 1 => {
            "The rustc commit hash is inferred from a /rustc/<40-hex>/ path in read-only data. It does not by itself prove which compiler produced the binary."
        }
        Some(_) => {
            "Read-only data contains more than one /rustc/<40-hex>/ path, so a single rustc commit is unknown."
        }
    }
}

fn text(value: impl Into<String>) -> Detail {
    Detail::Text(value.into())
}
fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", text(OPERATION))])
}
pub fn invalid(reason: &'static str, message: String) -> Failure {
    crate::artifacts::inspection::invalid_for(OPERATION, reason, message)
}

fn execution(path: &str, reason: String) -> Failure {
    let mut fields = details();
    fields.insert("provider_id", text(PROVIDER.id));
    fields.insert(
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
        fields,
    )
}
fn resource(kind: &'static str, reason: String, limit: &'static str, maximum: usize) -> Failure {
    let mut fields = details();
    fields.insert("resource", text(kind));
    fields.insert("reason", text(reason.clone()));
    fields.insert(
        "reported_limits",
        Detail::Fields(BTreeMap::from([(limit, Detail::Count(maximum as u64))])),
    );
    let action = match kind {
        "capacity" => {
            "Wait for an active analysis to complete, then retry within the reported admission limits."
        }
        "transport" => {
            "Discover retained records with get_evidence_bundle and detail: summary, then inspect compatible records through inspect_analysis_view using an exact Evidence reference. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable."
        }
        "file-size" => {
            "Review the reported worker file-size limits and write failure. Retry with a sufficient file-size allowance for the evidence reply; REA retains tighter inherited limits."
        }
        _ => {
            "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits."
        }
    };
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason,
        kind == "capacity",
        action.into(),
        fields,
    )
}
fn image_failure(error: image::Error, path: &str) -> Failure {
    match error {
        image::Error::Container(image::ContainerError::Unsupported(reason)) => {
            let mut fields = details();
            fields.insert("path", text(path));
            fields.insert("reason", text(reason));
            Failure::new(
                "unsupported_target",
                "unsupported_target",
                format!("Unsupported target for {OPERATION} at {path}: {reason}"),
                false,
                "Select a target supported by this operation or choose an operation supporting the reported target format."
                    .into(),
                fields,
            )
        }
        image::Error::Container(image::ContainerError::StructureLimit) => resource(
            "memory",
            format!(
                "Selected artifact {path}: native structure exceeds the 16 MiB decoding budget"
            ),
            "maximum_bytes",
            16 * 1024 * 1024,
        ),
        image::Error::InputLimit => resource(
            "file-size",
            format!(
                "Selected artifact exceeds {} bytes: {path}",
                image::MAX_INPUT_BYTES
            ),
            "maximum_input_bytes",
            image::MAX_INPUT_BYTES,
        ),
        image::Error::CompilerHashLimit => resource(
            "capacity",
            format!(
                "Selected artifact {path}: Read-only data contains more than 64 distinct rustc commit paths."
            ),
            "maximum_rustc_hashes",
            64,
        ),
        image::Error::Metadata(auditable::Error::Resource { stage, maximum }) => {
            let transport = matches!(stage, "normalized output" | "graph expansion");
            let (resource_kind, limit_name) = if transport {
                ("transport", "maximum_output_bytes")
            } else {
                ("memory", "maximum_bytes")
            };
            resource(
                resource_kind,
                format!("Selected artifact {path}: {stage} exceeds {maximum} bytes"),
                limit_name,
                maximum,
            )
        }
        image::Error::Metadata(auditable::Error::Encoding(error)) => {
            execution(path, error.to_string())
        }
        other => invalid(
            "invalid_format",
            format!("Selected artifact {path}: {other}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::cancellation::Cancellation;
    use rea_host::fs::stable_file::{self, FileAccess, FileError, Fingerprint, IoKind, Kind};
    use std::{
        io,
        path::Path,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct FakeFiles {
        bytes: Vec<u8>,
        close_failures: AtomicUsize,
        fail_read: AtomicBool,
        released_close_error: AtomicBool,
        cancel_on_close: AtomicBool,
        cancellation: Cancellation,
    }

    struct FakeHandle {
        bytes: Vec<u8>,
        offset: AtomicUsize,
    }

    impl FakeFiles {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                close_failures: AtomicUsize::new(0),
                fail_read: AtomicBool::new(false),
                released_close_error: AtomicBool::new(false),
                cancel_on_close: AtomicBool::new(false),
                cancellation: Cancellation::default(),
            }
        }

        fn fingerprint(&self) -> Fingerprint {
            Fingerprint {
                kind: Kind::Regular,
                device: 1,
                file_id: 2,
                bytes: self.bytes.len() as u64,
                modified_ns: 3,
                changed_ns: 4,
            }
        }
    }

    impl FileAccess for FakeFiles {
        type Handle = FakeHandle;

        fn lstat(&self, _path: &Path) -> Result<Fingerprint, FileError> {
            Ok(self.fingerprint())
        }

        fn open_regular_candidate(&self, _path: &Path) -> Result<Self::Handle, FileError> {
            Ok(FakeHandle {
                bytes: self.bytes.clone(),
                offset: AtomicUsize::new(0),
            })
        }

        fn stat(&self, _handle: &Self::Handle) -> Result<Fingerprint, FileError> {
            Ok(self.fingerprint())
        }

        fn read(&self, handle: &Self::Handle, output: &mut [u8]) -> Result<usize, FileError> {
            if self.fail_read.load(Ordering::SeqCst) {
                return Err(close_error("injected read failure"));
            }

            let offset = handle.offset.load(Ordering::SeqCst);
            let remaining = &handle.bytes[offset..];
            let count = remaining.len().min(output.len());
            output[..count].copy_from_slice(&remaining[..count]);
            handle.offset.fetch_add(count, Ordering::SeqCst);
            Ok(count)
        }

        fn close(&self, handle: Self::Handle) -> stable_file::CloseOutcome<Self::Handle> {
            if self.cancel_on_close.swap(false, Ordering::SeqCst) {
                self.cancellation
                    .cancel("cancelled during descriptor finalization");
            }

            if self
                .close_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return stable_file::CloseOutcome::Retained {
                    handle,
                    error: close_error("retained close failed"),
                };
            }

            if self.released_close_error.load(Ordering::SeqCst) {
                return stable_file::CloseOutcome::ReleasedWithError(close_error(
                    "released close returned an error",
                ));
            }

            stable_file::CloseOutcome::Released
        }
    }

    fn close_error(message: &'static str) -> FileError {
        FileError {
            kind: IoKind::AccessDenied,
            system_code: Some("EACCES"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, message),
        }
    }

    fn failure_value(failure: &Failure) -> serde_json::Value {
        serde_json::to_value(failure).expect("native failures serialize")
    }

    #[test]
    fn one_shot_retry_reports_released_owner_and_keeps_the_initial_close_error() {
        let files = Arc::new(FakeFiles::new(b"not a native image"));
        files.close_failures.store(1, Ordering::SeqCst);
        let mut inspection = RustInspection::new(files.clone());

        let failure = inspection
            .inspect("/fixture.bin", &files.cancellation, Completion::OneShot)
            .unwrap_err();
        let value = failure_value(&failure);

        assert_eq!(failure.code(), "execution_failure");
        assert_eq!(
            value["details"]["cleanup_failures"][0]["resource_released"],
            false
        );
        assert_eq!(value["details"]["cleanup_retry"], "released");
        assert!(inspection.close().is_ok());
    }

    #[test]
    fn repeated_failed_retries_preserve_every_attempt_and_the_exact_resource() {
        let files = Arc::new(FakeFiles::new(b"not a native image"));
        files.close_failures.store(3, Ordering::SeqCst);
        let mut inspection = RustInspection::new(files.clone());

        let first = inspection
            .inspect("/fixture.bin", &files.cancellation, Completion::OneShot)
            .unwrap_err();
        let first_value = failure_value(&first);
        assert_eq!(first.code(), "cleanup_incomplete");
        assert_eq!(first_value["details"]["resources"][0], "/fixture.bin");
        assert_eq!(
            first_value["details"]["cleanup_failures"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let second = inspection.close().unwrap_err();
        let second_value = failure_value(&second);
        assert_eq!(second.code(), "cleanup_incomplete");
        assert_eq!(second_value["details"]["resources"][0], "/fixture.bin");
        assert_eq!(
            second_value["details"]["cleanup_failures"]
                .as_array()
                .unwrap()
                .len(),
            3
        );

        assert!(inspection.close().is_ok());
    }

    #[test]
    fn primary_read_failure_survives_retained_cleanup_failure() {
        let files = Arc::new(FakeFiles::new(b"not a native image"));
        files.fail_read.store(true, Ordering::SeqCst);
        files.close_failures.store(1, Ordering::SeqCst);
        let mut inspection = RustInspection::new(files.clone());

        let failure = inspection
            .inspect("/fixture.bin", &files.cancellation, Completion::Session)
            .unwrap_err();
        let value = failure_value(&failure);

        assert_eq!(failure.code(), "cleanup_incomplete");
        assert_eq!(value["details"]["primary_failure"]["code"], "access_denied");
        assert_eq!(value["details"]["resources"][0], "/fixture.bin");
        assert_eq!(
            value["details"]["cleanup_failures"][0]["resource_released"],
            false
        );
        assert!(inspection.close().is_ok());
    }

    #[test]
    fn close_attempts_every_independent_retained_owner() {
        let files = Arc::new(FakeFiles::new(b"not a native image"));
        files.close_failures.store(2, Ordering::SeqCst);
        let mut inspection = RustInspection::new(files.clone());

        assert!(
            inspection
                .inner
                .read_snapshot("/first.bin", &files.cancellation, Completion::Session)
                .is_err()
        );
        assert!(
            inspection
                .inner
                .read_snapshot("/second.bin", &files.cancellation, Completion::Session)
                .is_err()
        );
        files.close_failures.store(2, Ordering::SeqCst);

        let failure = inspection.close().unwrap_err();
        let value = failure_value(&failure);

        assert_eq!(failure.code(), "cleanup_incomplete");
        assert_eq!(value["details"]["resources"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["details"]["cleanup_failures"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert!(inspection.close().is_ok());
    }

    #[test]
    fn released_close_error_is_reported_without_claiming_a_retained_resource() {
        let files = Arc::new(FakeFiles::new(b"not a native image"));
        files.released_close_error.store(true, Ordering::SeqCst);
        let mut inspection = RustInspection::new(files.clone());

        let failure = inspection
            .inspect("/fixture.bin", &files.cancellation, Completion::Session)
            .unwrap_err();
        let value = failure_value(&failure);

        assert_eq!(failure.code(), "execution_failure");
        assert!(value["details"].get("cleanup").is_none());
        assert_eq!(
            value["details"]["cleanup_failures"][0]["resource_released"],
            true
        );
        assert!(inspection.close().is_ok());
    }

    #[test]
    fn cancellation_during_close_keeps_its_reason_and_does_not_parse_the_snapshot() {
        let files = Arc::new(FakeFiles::new(b"not a native image"));
        files.cancel_on_close.store(true, Ordering::SeqCst);
        let mut inspection = RustInspection::new(files.clone());

        let failure = inspection
            .inspect("/fixture.bin", &files.cancellation, Completion::Session)
            .unwrap_err();
        let value = failure_value(&failure);

        assert_eq!(failure.code(), "cancelled");
        assert_eq!(
            value["details"]["cancellation_reason"],
            "cancelled during descriptor finalization"
        );
        assert!(inspection.close().is_ok());
    }
}
