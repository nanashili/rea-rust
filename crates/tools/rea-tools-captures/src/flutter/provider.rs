//! Flutter build identification by pure APK parsing.
//!
//! Compatibility owners: `src/flutter/FlutterBuildProvider.ts`,
//! `src/application/flutter/FlutterBuildAnalysisService.ts`,
//! `src/application/ProviderOperationExecution.ts` and
//! `src/application/AnalysisProvider.ts` (`createAnalysisExecution`).
//!
//! The TypeScript provider owns a read-only snapshot of the admitted APK, a
//! hardened streaming ZIP reader and per-library streaming scanners. This port
//! acquires the snapshot through the shared stable artifact read (identity
//! revalidation and digest) and runs the ported ZIP reader and scanners over
//! the buffered bytes.

use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{EvidenceProvider, Observation, SubjectTarget};
use regex::Regex;
use serde_json::{Value, json};

use crate::artifact::{self, ReadError, ReaderReason};
use crate::errors::{self, object};
use crate::flutter::dart_elf::{
    ELF_HEADER_MAX_BYTES, SnapshotHeader, elf_header_valid, read_elf_symbols, read_snapshot_header,
};
use crate::flutter::elf_build_id::read_elf_build_ids;
use crate::flutter::payload_scan::{
    LabeledStringScanner, MAX_SNAPSHOT_HASH_CANDIDATES, SnapshotHashScanner,
};
use crate::flutter::zip::{ZipEntry, ZipEntryKind, ZipFailure, ZipFailureReason, ZipReader};

/// Stable identity for the Flutter build-identification provider.
pub const PROVIDER_ID: &str = "flutter";
pub const PROVIDER_NAME: &str = "Flutter build identification";

pub fn provider_identity() -> EvidenceProvider {
    EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, None)
}

/// Full logical ZIP path budget, enforced by Flutter library inventory.
const MAX_FLUTTER_LIBRARY_PATH_BYTES: usize = 1024;
const LIBRARY_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Cumulative cap across every library entry in one identification.
const TOTAL_EXTRACTION_MAX_BYTES: u64 = 768 * 1024 * 1024;
/// The APK itself must fit within this budget before any copy.
const APK_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_FLUTTER_ABIS: usize = 32;
const MAX_POOL_URIS: usize = 500;
const MAX_POOL_TOKENS: usize = 2_000;
/// A complete AOT image carries exactly one VM and one isolate section.
const SYMBOL_PAIR_COUNT: usize = 2;

const DART_SYMBOL_NAMES: [&str; 4] = [
    "_kDartVmSnapshotData",
    "_kDartVmSnapshotInstructions",
    "_kDartIsolateSnapshotData",
    "_kDartIsolateSnapshotInstructions",
];

/// A successful provider observation ready for Evidence composition.
pub struct Execution {
    pub result: Value,
    pub subject: SubjectTarget,
    pub locations: Vec<Value>,
    pub limitations: Vec<String>,
}

#[derive(Clone)]
struct FlutterLibrary {
    entry: ZipEntry,
    abi: String,
    kind: LibraryKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LibraryKind {
    Libapp,
    Libflutter,
}

#[derive(Clone, Default)]
struct LibappFacts {
    present: bool,
    bytes: Option<u64>,
    sha256: Option<String>,
    elf_header_valid: Option<bool>,
    sources: usize,
    candidates: Vec<String>,
}

#[derive(Clone, Default)]
struct LibflutterFacts {
    present: bool,
    bytes: Option<u64>,
    sha256: Option<String>,
    build_id: Option<String>,
    build_id_candidates: Vec<String>,
    build_id_failures: Vec<String>,
    dart_version: Option<String>,
    dart_version_capped: bool,
    toolchain_lines: Vec<String>,
    toolchain_capped: bool,
}

#[derive(Clone, Default)]
struct LibraryFacts {
    libapp: LibappFacts,
    libflutter: LibflutterFacts,
}

/// Run one caller-selected request and build its atomic execution.
pub fn execute(
    operation: &str,
    path: &str,
    abi: Option<&str>,
    cancellation: &Cancellation,
) -> Result<Execution, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }

    let acquired = acquire_snapshot(operation, path, cancellation)?;
    // The reader owns the only copy of the snapshot bytes; the identity facts
    // stay separate so the APK is not resident twice.
    let snapshot = SnapshotIdentity {
        bytes: acquired.bytes.len(),
        sha256: acquired.sha256,
    };
    if snapshot.bytes as u64 > APK_MAX_BYTES {
        return Err(errors::resource(
            operation,
            "file-size",
            &format!("The selected APK exceeds the {APK_MAX_BYTES}-byte snapshot budget"),
            Some(json!({
                "max_apk_bytes": APK_MAX_BYTES,
                "observed_bytes": snapshot.bytes,
            })),
        ));
    }

    let mut reader = ZipReader::new(acquired.bytes);
    let libraries = collect_flutter_libraries(&mut reader, operation, path)?;

    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }

    match operation {
        "inspect_dart_aot" => {
            inspect_dart_aot(path, abi, &snapshot, &reader, &libraries, cancellation)
        }
        _ => identify_flutter_build(path, &snapshot, &reader, &libraries, cancellation),
    }
}

struct Snapshot {
    bytes: Vec<u8>,
    sha256: String,
}
/// Identity of the acquired snapshot once its bytes moved into the reader.
struct SnapshotIdentity {
    bytes: usize,
    sha256: String,
}

/// Acquire the owned read-only snapshot (identity revalidation + digest).
fn acquire_snapshot(
    operation: &str,
    path: &str,
    cancellation: &Cancellation,
) -> Result<Snapshot, AnalysisError> {
    match artifact::read_stable(path, APK_MAX_BYTES as usize, cancellation) {
        Ok(snapshot) => Ok(Snapshot {
            bytes: snapshot.bytes,
            sha256: snapshot.sha256,
        }),
        Err(error) => Err(map_read_error(operation, path, &error)),
    }
}

/// Translate a stable-read failure into the typed analysis-error algebra,
/// following `mapInputFailure`/`mapOwnedIoFailure` in the TypeScript provider.
fn map_read_error(operation: &str, path: &str, error: &ReadError) -> AnalysisError {
    match error.reader_reason() {
        Some(ReaderReason::Cancelled) => AnalysisError::cancelled(operation),
        Some(ReaderReason::Path) => errors::input_issue(
            operation,
            vec![errors::segment("path")],
            "invalid_format",
            format!("Selected APK is not a regular file: {path}"),
        ),
        Some(ReaderReason::Limit) => errors::resource(
            operation,
            "file-size",
            &format!("The selected APK exceeds the {APK_MAX_BYTES}-byte snapshot budget"),
            Some(json!({ "max_apk_bytes": APK_MAX_BYTES })),
        ),
        Some(ReaderReason::Integrity) => AnalysisError::artifact_changed(
            operation,
            path,
            "Selected file identity or contents changed during snapshotting",
        ),
        _ => {
            if error.system_code() == Some("EACCES") || error.system_code() == Some("EPERM") {
                return AnalysisError::access_denied(
                    operation,
                    path,
                    error.system_code().unwrap_or("EACCES"),
                );
            }
            let code = error.system_code();
            let message = if code == Some("ENOENT") || code == Some("ENOTDIR") {
                format!("Selected APK does not exist: {path}")
            } else {
                format!(
                    "The APK could not be read as a package: {path}: {}",
                    error.message()
                )
            };
            errors::input_issue(
                operation,
                vec![errors::segment("path")],
                "invalid_format",
                message,
            )
        }
    }
}

/// Map a ZIP reader failure the way `mapPackageFailure` does.
fn map_zip_failure(operation: &str, path: &str, failure: &ZipFailure) -> AnalysisError {
    match failure.reason {
        ZipFailureReason::Limit => errors::resource(operation, "memory", &failure.message, None),
        _ => errors::input_issue(
            operation,
            vec![errors::segment("path")],
            "invalid_format",
            format!(
                "The APK could not be read as a package: {path}: {}",
                failure.message
            ),
        ),
    }
}

/// One inventory owns occurrence ambiguity and metadata expansion for both tools.
fn collect_flutter_libraries(
    reader: &mut ZipReader,
    operation: &str,
    path: &str,
) -> Result<Vec<FlutterLibrary>, AnalysisError> {
    let pattern =
        Regex::new(r"^lib/([^/]+)/(libapp|libflutter)\.so$").expect("static library pattern");
    let entries = reader
        .entries()
        .map_err(|failure| map_zip_failure(operation, path, &failure))?;
    let mut libraries = Vec::new();
    let mut paths = std::collections::HashSet::new();
    let mut abis = std::collections::HashSet::new();
    for entry in entries {
        if !matches!(entry.kind, ZipEntryKind::File) {
            continue;
        }
        let captures = match pattern.captures(&entry.path) {
            Some(captures) => captures,
            None => continue,
        };
        if paths.contains(&entry.path) {
            return Err(errors::input_issue(
                operation,
                vec![errors::segment("path")],
                "invalid_format",
                format!(
                    "The selected APK has duplicate Flutter library members: {path}: {}",
                    entry.path
                ),
            ));
        }
        let abi = captures.get(1).unwrap().as_str().to_owned();
        let kind = if &captures[2] == "libapp" {
            LibraryKind::Libapp
        } else {
            LibraryKind::Libflutter
        };
        paths.insert(entry.path.clone());
        abis.insert(abi.clone());
        if abis.len() > MAX_FLUTTER_ABIS || entry.path.len() > MAX_FLUTTER_LIBRARY_PATH_BYTES {
            return Err(errors::resource(
                operation,
                "memory",
                "Flutter library inventory exceeds the bounded ABI projection budget",
                Some(json!({
                    "max_flutter_abis": MAX_FLUTTER_ABIS,
                    "max_library_path_bytes": MAX_FLUTTER_LIBRARY_PATH_BYTES,
                })),
            ));
        }
        libraries.push(FlutterLibrary { entry, abi, kind });
    }
    Ok(libraries)
}

fn identify_flutter_build(
    path: &str,
    snapshot: &SnapshotIdentity,
    reader: &ZipReader,
    flutter_entries: &[FlutterLibrary],
    cancellation: &Cancellation,
) -> Result<Execution, AnalysisError> {
    let operation = "identify_flutter_build";

    for library in flutter_entries {
        if let Some(declared) = library.entry.declared_size {
            if declared > LIBRARY_MAX_BYTES {
                return Err(errors::resource(
                    operation,
                    "file-size",
                    &format!("{} exceeds the library read budget", library.entry.path),
                    Some(
                        json!({ "max_library_bytes": LIBRARY_MAX_BYTES, "entry_path": library.entry.path }),
                    ),
                ));
            }
        }
    }

    let declared_total: u64 = flutter_entries
        .iter()
        .map(|library| library.entry.declared_size.unwrap_or(0))
        .sum();
    if declared_total > TOTAL_EXTRACTION_MAX_BYTES {
        return Err(errors::resource(
            operation,
            "file-size",
            &format!(
                "declared library sizes total {declared_total} bytes, exceeding the {TOTAL_EXTRACTION_MAX_BYTES}-byte cumulative budget before any extraction"
            ),
            Some(
                json!({ "max_total_bytes": TOTAL_EXTRACTION_MAX_BYTES, "declared_total": declared_total }),
            ),
        ));
    }

    // `facts` is a JavaScript `Map` in the oracle: keyed by ABI and iterated in
    // first-insertion (archive) order. Limitations for build-id failures use
    // that insertion order, while the `abis` array and the remaining limitation
    // blocks use the code-point-sorted order; both are derived below.
    let mut facts: Vec<(String, LibraryFacts)> = Vec::new();
    let mut extracted_total: u64 = 0;

    for library in flutter_entries {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let data = reader
            .open(&library.entry)
            .map_err(|failure| map_zip_failure(operation, path, &failure))?;
        let bytes = data.len() as u64;
        if bytes > LIBRARY_MAX_BYTES {
            return Err(errors::resource(
                operation,
                "file-size",
                &format!(
                    "{} exceeds the {LIBRARY_MAX_BYTES}-byte read budget while streaming",
                    library.entry.path
                ),
                Some(
                    json!({ "max_library_bytes": LIBRARY_MAX_BYTES, "entry_path": library.entry.path }),
                ),
            ));
        }
        if extracted_total + bytes > TOTAL_EXTRACTION_MAX_BYTES {
            return Err(errors::resource(
                operation,
                "file-size",
                &format!(
                    "cumulative library extraction across {} entries exceeds the {TOTAL_EXTRACTION_MAX_BYTES}-byte budget",
                    flutter_entries.len()
                ),
                Some(json!({ "max_total_bytes": TOTAL_EXTRACTION_MAX_BYTES })),
            ));
        }
        extracted_total += bytes;

        let digest = artifact::sha256_hex(&data);
        let current = match facts.iter_mut().position(|(abi, _)| *abi == library.abi) {
            Some(index) => &mut facts[index].1,
            None => {
                facts.push((library.abi.clone(), LibraryFacts::default()));
                &mut facts.last_mut().unwrap().1
            }
        };
        match library.kind {
            LibraryKind::Libapp => {
                let mut scanner = SnapshotHashScanner::new();
                scanner.push(&data);
                let scan = scanner.result();
                if scan.capped {
                    return Err(errors::resource(
                        operation,
                        "memory",
                        "Snapshot hash candidates exceed the retained evidence budget",
                        Some(json!({
                            "max_snapshot_hash_candidates": MAX_SNAPSHOT_HASH_CANDIDATES,
                            "entry_path": library.entry.path,
                        })),
                    ));
                }
                let header_prefix = &data[..data.len().min(ELF_HEADER_MAX_BYTES)];
                current.libapp = LibappFacts {
                    present: true,
                    bytes: Some(bytes),
                    sha256: Some(digest),
                    elf_header_valid: Some(elf_header_valid(header_prefix, bytes as usize)),
                    sources: scan.sources,
                    candidates: scan.candidates,
                };
            }
            LibraryKind::Libflutter => {
                let mut scanner = LabeledStringScanner::new();
                scanner.push(&data);
                let labeled = scanner.result();
                let build_ids = read_elf_build_ids(&data, bytes as usize);
                let build_id = if build_ids.failures.is_empty() && build_ids.candidates.len() == 1 {
                    Some(build_ids.candidates[0].clone())
                } else {
                    None
                };
                current.libflutter = LibflutterFacts {
                    present: true,
                    bytes: Some(bytes),
                    sha256: Some(digest),
                    build_id,
                    build_id_candidates: build_ids.candidates,
                    build_id_failures: build_ids.failures,
                    dart_version: labeled.dart_version,
                    dart_version_capped: labeled.dart_version_capped,
                    toolchain_lines: labeled.toolchain_lines,
                    toolchain_capped: labeled.toolchain_capped,
                };
            }
        }
    }

    // `facts` holds archive insertion order; the `abis` array and the sorted
    // limitation blocks use Unicode code-point order (= Rust `str` order).
    let mut sorted: Vec<&(String, LibraryFacts)> = facts.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    // Project per-ABI records in code-point order.
    let mut abi_values: Vec<Value> = Vec::new();
    for (abi, value) in &sorted {
        let libapp_hash = if value.libapp.candidates.len() == 1 {
            json!(value.libapp.candidates[0])
        } else {
            Value::Null
        };
        let libapp = object([
            ("present", json!(value.libapp.present)),
            ("bytes", opt_u64(value.libapp.bytes)),
            ("sha256", errors::nullable(value.libapp.sha256.as_deref())),
            ("elf_header_valid", opt_bool(value.libapp.elf_header_valid)),
            ("snapshot_hash_sources", json!(value.libapp.sources)),
            ("snapshot_hash_candidates", json!(value.libapp.candidates)),
            ("snapshot_hash", libapp_hash),
        ]);
        let libflutter = object([
            ("present", json!(value.libflutter.present)),
            ("bytes", opt_u64(value.libflutter.bytes)),
            (
                "sha256",
                errors::nullable(value.libflutter.sha256.as_deref()),
            ),
            (
                "build_id",
                errors::nullable(value.libflutter.build_id.as_deref()),
            ),
            (
                "build_id_candidates",
                json!(value.libflutter.build_id_candidates),
            ),
            (
                "dart_version",
                errors::nullable(value.libflutter.dart_version.as_deref()),
            ),
            (
                "dart_version_capped",
                json!(value.libflutter.dart_version_capped),
            ),
            ("toolchain_lines", json!(value.libflutter.toolchain_lines)),
            ("toolchain_capped", json!(value.libflutter.toolchain_capped)),
        ]);
        abi_values.push(object([
            ("abi", json!(abi)),
            ("libapp", libapp),
            ("libflutter", libflutter),
        ]));
    }

    let flutter_detected = facts.iter().any(|(_, value)| value.libapp.present);

    let partial = facts.iter().any(|(_, value)| {
        (value.libapp.present
            && (value.libapp.candidates.len() != 1
                || value.libapp.sources != 2
                || value.libapp.elf_header_valid != Some(true)))
            || value.libflutter.toolchain_capped
            || value.libflutter.dart_version_capped
            || value.libapp.present != value.libflutter.present
    }) || facts.iter().any(|(_, value)| {
        !value.libflutter.build_id_failures.is_empty()
            || value.libflutter.build_id_candidates.len() > 1
    });

    let mut limitations: Vec<String> = vec![
        "The APK is read through an owned read-only snapshot; concurrent changes to the original cannot mix into this observation".into(),
        "The snapshot hash identifies a Dart SDK build only against an external mapping dataset; REA performs no lookup".into(),
        "Release engine builds often carry no labeled Dart version string; absence is reported, not guessed".into(),
        "Engine build IDs come only from ELF-declared PT_NOTE/SHT_NOTE records; conflicting or incompletely examined notes preserve candidates and report partial coverage".into(),
    ];
    // Build-id failures/conflicts follow archive (insertion) order in the oracle.
    for (abi, value) in &facts {
        for reason in &value.libflutter.build_id_failures {
            limitations.push(format!("lib/{abi}/libflutter.so: {reason}"));
        }
        if value.libflutter.build_id_candidates.len() > 1 {
            limitations.push(format!(
                "lib/{abi}/libflutter.so has conflicting GNU build IDs"
            ));
        }
    }
    for (abi, value) in &sorted {
        if value.libflutter.toolchain_capped {
            limitations.push(format!(
                "lib/{abi}/libflutter.so has toolchain labels omitted by the complete-label grammar or the 4-line projection"
            ));
        }
    }
    for (abi, value) in &sorted {
        if value.libflutter.dart_version_capped {
            limitations.push(format!(
                "lib/{abi}/libflutter.so has Dart version labels omitted by the complete-label grammar or the single-version projection"
            ));
        }
    }
    limitations.push(
        "The snapshot hash sits 20 bytes after each snapshot magic in the AOT payload; findings are observations of that layout".into(),
    );
    limitations.push(
        "ELF header validity checks the supported header layout and declared table extents; identification does not resolve symbols or validate table contents".into(),
    );
    for (abi, value) in &sorted {
        if value.libapp.present && value.libapp.sources != 2 {
            limitations.push(format!(
                "lib/{abi}/libapp.so carries {} snapshot section(s); a complete AOT payload carries two, so the library is truncated or nonstandard",
                value.libapp.sources
            ));
        }
    }
    for (abi, value) in &sorted {
        if value.libapp.present && value.libapp.elf_header_valid != Some(true) {
            limitations.push(format!(
                "lib/{abi}/libapp.so has a truncated, malformed, or unsupported ELF header or table extent; byte-scanned hashes remain observations only"
            ));
        }
    }
    if !flutter_detected {
        limitations.push(
            "No lib/*/libapp.so was found; the target does not carry a Flutter AOT payload".into(),
        );
    }

    let result = object([
        ("target", target_value(path, snapshot)),
        ("flutter_detected", json!(flutter_detected)),
        ("abis", Value::Array(abi_values)),
        (
            "coverage",
            json!(if partial { "partial" } else { "complete" }),
        ),
    ]);

    Ok(Execution {
        result,
        subject: SubjectTarget {
            path: path.to_owned(),
            sha256: snapshot.sha256.clone(),
            format: "apk".into(),
            architecture: None,
        },
        locations: vec![json!({ "kind": "artifact-path", "path": path })],
        limitations,
    })
}

fn inspect_dart_aot(
    path: &str,
    abi: Option<&str>,
    snapshot: &SnapshotIdentity,
    reader: &ZipReader,
    libraries: &[FlutterLibrary],
    cancellation: &Cancellation,
) -> Result<Execution, AnalysisError> {
    let operation = "inspect_dart_aot";
    let candidates: Vec<&FlutterLibrary> = libraries
        .iter()
        .filter(|library| matches!(library.kind, LibraryKind::Libapp))
        .collect();
    if candidates.is_empty() {
        return Err(AnalysisError::unsupported_target(
            operation,
            path,
            "No lib/<abi>/libapp.so was found; the target carries no Dart AOT payload",
        ));
    }

    let preference = ["arm64-v8a", "x86_64", "x86", "armeabi-v7a"];
    let rank = |abi: &str| -> usize {
        preference
            .iter()
            .position(|value| *value == abi)
            .map_or(preference.len() + 1, |index| index + 1)
    };

    let selected: Option<&FlutterLibrary> = match abi {
        None => {
            let mut sorted = candidates.clone();
            sorted.sort_by(|left, right| {
                rank(&left.abi)
                    .cmp(&rank(&right.abi))
                    .then_with(|| left.abi.cmp(&right.abi))
            });
            sorted.first().copied()
        }
        Some(abi) => candidates
            .iter()
            .copied()
            .find(|candidate| candidate.abi == abi),
    };

    let selected = match selected {
        Some(selected) => selected,
        None => {
            let available = candidates
                .iter()
                .map(|candidate| candidate.abi.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(AnalysisError::unsupported_target(
                operation,
                path,
                format!(
                    "No libapp.so was found for ABI {}; available: {available}",
                    abi.unwrap_or("(none)")
                ),
            ));
        }
    };

    let declared = selected
        .entry
        .declared_size
        .unwrap_or(LIBRARY_MAX_BYTES + 1);
    if declared > LIBRARY_MAX_BYTES {
        return Err(errors::resource(
            operation,
            "file-size",
            &format!(
                "lib/{}/libapp.so declares {declared} bytes, exceeding the {LIBRARY_MAX_BYTES}-byte read budget",
                selected.abi
            ),
            Some(json!({ "max_library_bytes": LIBRARY_MAX_BYTES })),
        ));
    }

    let image = reader
        .open(&selected.entry)
        .map_err(|failure| map_zip_failure(operation, path, &failure))?;
    if image.len() as u64 > LIBRARY_MAX_BYTES {
        return Err(errors::resource(
            operation,
            "file-size",
            &format!(
                "lib/{}/libapp.so exceeds the {LIBRARY_MAX_BYTES}-byte read budget while streaming",
                selected.abi
            ),
            Some(json!({ "max_library_bytes": LIBRARY_MAX_BYTES })),
        ));
    }
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    let image_sha256 = artifact::sha256_hex(&image);
    let image_length = image.len();
    let bounded = &image[..image_length];

    let inventory = read_elf_symbols(bounded, &DART_SYMBOL_NAMES);

    struct SectionRecord {
        name: String,
        offset: usize,
        size: usize,
        magic_valid: bool,
        kind: Option<u64>,
        header_length: Option<u64>,
    }
    struct DataHeader {
        name: String,
        offset: usize,
        size: usize,
        header: SnapshotHeader,
    }

    let mut sections: Vec<SectionRecord> = Vec::new();
    let mut data_headers: Vec<DataHeader> = Vec::new();
    let mut isolate_data: Option<Vec<u8>> = None;

    for symbol in &inventory.symbols {
        let header = if symbol.name.ends_with("Data") {
            let end = (symbol.offset + symbol.size).min(image.len());
            Some(read_snapshot_header(&image[symbol.offset..end], 0))
        } else {
            None
        };
        sections.push(SectionRecord {
            name: symbol.name.clone(),
            offset: symbol.offset,
            size: symbol.size,
            magic_valid: header
                .as_ref()
                .map(|header| header.magic_valid)
                .unwrap_or(false),
            kind: header.as_ref().and_then(|header| header.kind),
            header_length: header.as_ref().and_then(|header| header.header_length),
        });
        if let Some(header) = header {
            data_headers.push(DataHeader {
                name: symbol.name.clone(),
                offset: symbol.offset,
                size: symbol.size,
                header,
            });
        }
        if symbol.name == "_kDartIsolateSnapshotData" {
            let end = (symbol.offset + symbol.size).min(image.len());
            isolate_data = Some(image[symbol.offset..end].to_vec());
        }
    }

    // Each exported data symbol owns one header at its start.
    let mut observed_offsets = std::collections::HashSet::new();
    let mut aliased_data_symbols = false;
    let mut hashes: Vec<String> = Vec::new();
    for section in &data_headers {
        if observed_offsets.contains(&section.offset) {
            aliased_data_symbols = true;
            continue;
        }
        observed_offsets.insert(section.offset);
        if let Some(hash) = &section.header.hash {
            hashes.push(hash.clone());
        }
    }
    let hash_sources = hashes.len();
    let hash_candidates: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        let mut distinct = Vec::new();
        for hash in &hashes {
            if seen.insert(hash.clone()) {
                distinct.push(hash.clone());
            }
        }
        distinct
    };

    let overlapping_data_symbols = data_headers.iter().enumerate().any(|(index, section)| {
        data_headers[..index].iter().any(|previous| {
            previous.offset < section.offset + section.size
                && section.offset < previous.offset + previous.size
        })
    });

    if sections.is_empty() {
        let joined = inventory.failures.join("; ");
        return Err(AnalysisError::unsupported_target(
            operation,
            path,
            format!("No recognizable Dart snapshot symbols were found: {joined}"),
        ));
    }

    let pool = project_string_pool(operation, isolate_data.as_deref(), cancellation)?;

    let snapshot_partial = !inventory.failures.is_empty()
        || aliased_data_symbols
        || overlapping_data_symbols
        || sections.len() < DART_SYMBOL_NAMES.len()
        || data_headers.len() != SYMBOL_PAIR_COUNT
        || data_headers.iter().any(|section| !section.header.complete)
        || hash_candidates.len() != 1
        || hash_sources != SYMBOL_PAIR_COUNT;

    let pool_partial = isolate_data.is_none()
        || pool.collection_capped
        || pool.package_uri_count > MAX_POOL_URIS
        || pool.dart_uri_count > MAX_POOL_URIS
        || pool.class_like_token_count > MAX_POOL_TOKENS;

    let section_values: Vec<Value> = sections
        .iter()
        .map(|section| {
            object([
                ("name", json!(section.name)),
                ("offset", json!(section.offset)),
                ("size", json!(section.size)),
                ("magic_valid", json!(section.magic_valid)),
                ("kind", opt_u64(section.kind)),
                ("header_length", opt_u64(section.header_length)),
            ])
        })
        .collect();

    let libapp = object([
        (
            "coverage",
            json!(if snapshot_partial {
                "partial"
            } else {
                "complete"
            }),
        ),
        ("bytes", json!(image_length)),
        ("sha256", json!(image_sha256)),
        (
            "snapshot_hash",
            if hash_candidates.len() == 1 {
                json!(hash_candidates[0])
            } else {
                Value::Null
            },
        ),
        ("snapshot_hash_candidates", json!(hash_candidates)),
        ("snapshot_hash_sources", json!(hash_sources)),
        ("sections", Value::Array(section_values)),
    ]);

    let string_pool = object([
        (
            "coverage",
            json!(if pool_partial { "partial" } else { "complete" }),
        ),
        (
            "package_uris",
            json!(take(&pool.package_uris, MAX_POOL_URIS)),
        ),
        ("package_uri_count_at_least", json!(pool.package_uri_count)),
        ("dart_uris", json!(take(&pool.dart_uris, MAX_POOL_URIS))),
        ("dart_uri_count_at_least", json!(pool.dart_uri_count)),
        (
            "class_like_tokens",
            json!(take(&pool.class_like_tokens, MAX_POOL_TOKENS)),
        ),
        (
            "class_like_token_count_at_least",
            json!(pool.class_like_token_count),
        ),
        ("printable_run_count", json!(pool.printable_run_count)),
    ]);

    let result = object([
        ("target", target_value(path, snapshot)),
        ("abi", json!(selected.abi)),
        ("libapp", libapp),
        ("string_pool", string_pool),
        (
            "coverage",
            json!(if snapshot_partial || pool_partial {
                "partial"
            } else {
                "complete"
            }),
        ),
    ]);

    let mut limitations: Vec<String> = vec![
        "The APK is read through an owned read-only snapshot; concurrent changes to the original cannot mix into this observation".into(),
        "Snapshot sections are located through the ELF dynamic symbol table; a payload without exported snapshot symbols is refused rather than guessed".into(),
        "Snapshot hash sources are the headers at the start of the VM and isolate data symbols; complete decoding supports kind 3 (the Dart 2.14 FullAOT layout), a valid hash and a declared length that fits its symbol, including the four magic bytes; other kind values remain observed with partial coverage".into(),
        "String-pool entries are byte-pattern observations from the isolate data section, not deserialized cluster semantics; typed class and function recovery needs an SDK-specific parser".into(),
        "class_like_tokens are identifier-shaped runs and include incidental matches".into(),
        "string-pool counts are lower bounds: collection stops at twice each projection bound, and any value beyond that is counted only through the capped flag".into(),
    ];
    for failure in &inventory.failures {
        limitations.push(failure.clone());
    }
    if sections.len() < DART_SYMBOL_NAMES.len() {
        limitations.push(format!(
            "Only {} of 4 snapshot symbols were present",
            sections.len()
        ));
    }
    if aliased_data_symbols {
        limitations.push(
            "Two or more snapshot data symbols share one header offset; its hash counts as one source instead of two agreeing ones".into(),
        );
    }
    if overlapping_data_symbols && !aliased_data_symbols {
        limitations.push(
            "Snapshot data symbol ranges overlap; independent VM/isolate coverage is not established".into(),
        );
    }
    for section in data_headers
        .iter()
        .filter(|section| !section.header.complete)
    {
        limitations.push(format!(
            "{} has an incomplete or invalid snapshot header: kind {} (AOT app requires 3), declared length {} excludes the four magic bytes, symbol size {}, valid hash {}",
            section.name,
            option_display(section.header.kind),
            option_display(section.header.header_length),
            section.size,
            section.header.hash.is_some()
        ));
    }
    if pool.collection_capped {
        limitations.push(
            "String-pool collection or printable-run capacity was exceeded; counts are lower bounds and overflowed runs are omitted".into(),
        );
    }
    if pool.dart_uri_count > MAX_POOL_URIS {
        limitations.push(format!(
            "dart_uris reports {MAX_POOL_URIS} of at least {} distinct URIs",
            pool.dart_uri_count
        ));
    }
    if pool.package_uri_count > MAX_POOL_URIS {
        limitations.push(format!(
            "package_uris reports {MAX_POOL_URIS} of at least {} distinct URIs",
            pool.package_uri_count
        ));
    }
    if pool.class_like_token_count > MAX_POOL_TOKENS {
        limitations.push(format!(
            "class_like_tokens reports {MAX_POOL_TOKENS} of at least {} distinct tokens",
            pool.class_like_token_count
        ));
    }

    Ok(Execution {
        result,
        subject: SubjectTarget {
            path: path.to_owned(),
            sha256: snapshot.sha256.clone(),
            format: "apk".into(),
            architecture: None,
        },
        locations: vec![json!({ "kind": "artifact-path", "path": path })],
        limitations,
    })
}

fn target_value(path: &str, snapshot: &SnapshotIdentity) -> Value {
    object([
        ("path", json!(path)),
        ("bytes", json!(snapshot.bytes)),
        ("sha256", json!(snapshot.sha256)),
    ])
}

fn opt_u64(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |value| json!(value))
}

fn opt_bool(value: Option<bool>) -> Value {
    value.map_or(Value::Null, |value| json!(value))
}

fn option_display<T: std::fmt::Display>(value: Option<T>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".to_owned(),
    }
}

fn take(values: &[String], limit: usize) -> Vec<String> {
    values.iter().take(limit).cloned().collect()
}

/// Build the Evidence provider observation for one successful execution.
pub fn observation(operation: &str, input: &Value, execution: &Execution) -> Observation {
    Observation::new(operation, input.clone(), execution.result.clone())
        .confidence("observed")
        .limitations(execution.limitations.clone())
        .locations(execution.locations.clone())
}

struct StringPool {
    package_uris: Vec<String>,
    package_uri_count: usize,
    dart_uris: Vec<String>,
    dart_uri_count: usize,
    class_like_tokens: Vec<String>,
    class_like_token_count: usize,
    printable_run_count: usize,
    collection_capped: bool,
}

/// Categorize printable runs from one snapshot data section.
fn project_string_pool(
    operation: &str,
    section: Option<&[u8]>,
    cancellation: &Cancellation,
) -> Result<StringPool, AnalysisError> {
    use std::collections::HashSet;
    let mut packages: HashSet<String> = HashSet::new();
    let mut darts: HashSet<String> = HashSet::new();
    let mut tokens: HashSet<String> = HashSet::new();
    let mut run_count = 0usize;
    let mut collection_capped = false;
    const COLLECTION_SLACK: usize = 2;
    const MAX_RUN_BYTES: usize = 1024;
    let package_budget = MAX_POOL_URIS * COLLECTION_SLACK;
    let dart_budget = MAX_POOL_URIS * COLLECTION_SLACK;
    let token_budget = MAX_POOL_TOKENS * COLLECTION_SLACK;
    let identifier = Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*$").expect("static identifier pattern");

    if let Some(section) = section {
        let mut run = String::new();
        let mut overflowed = false;

        let consider = |text: &str,
                        packages: &mut HashSet<String>,
                        darts: &mut HashSet<String>,
                        tokens: &mut HashSet<String>,
                        run_count: &mut usize,
                        collection_capped: &mut bool| {
            if text.chars().count() < 5 {
                return;
            }
            *run_count += 1;
            if text.starts_with("package:") {
                if !packages.contains(text) && packages.len() >= package_budget {
                    *collection_capped = true;
                } else {
                    packages.insert(text.to_owned());
                }
            } else if text.starts_with("dart:") {
                if !darts.contains(text) && darts.len() >= dart_budget {
                    *collection_capped = true;
                } else {
                    darts.insert(text.to_owned());
                }
            } else {
                let length = text.chars().count();
                if (5..=128).contains(&length) && identifier.is_match(text) {
                    if !tokens.contains(text) && tokens.len() >= token_budget {
                        *collection_capped = true;
                    } else {
                        tokens.insert(text.to_owned());
                    }
                }
            }
        };

        // Scan in 64 KiB windows, checking cancellation at each boundary like
        // the TypeScript `yieldToEventLoop` + `signal?.throwIfAborted()` cadence.
        const SCAN_WINDOW: usize = 64 * 1024;
        let mut start = 0usize;
        while start < section.len() {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(operation));
            }
            let end = (start + SCAN_WINDOW).min(section.len());
            for &byte in &section[start..end] {
                if (0x20..0x7f).contains(&byte) {
                    if run.len() < MAX_RUN_BYTES {
                        run.push(byte as char);
                    } else {
                        overflowed = true;
                        collection_capped = true;
                    }
                } else {
                    if !overflowed {
                        consider(
                            &run,
                            &mut packages,
                            &mut darts,
                            &mut tokens,
                            &mut run_count,
                            &mut collection_capped,
                        );
                    }
                    overflowed = false;
                    run.clear();
                }
            }
            start = end;
        }
        if !overflowed {
            consider(
                &run,
                &mut packages,
                &mut darts,
                &mut tokens,
                &mut run_count,
                &mut collection_capped,
            );
        }
    }
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }

    let mut package_uris: Vec<String> = packages.iter().cloned().collect();
    package_uris.sort();
    let mut dart_uris: Vec<String> = darts.iter().cloned().collect();
    dart_uris.sort();
    let mut class_like_tokens: Vec<String> = tokens.iter().cloned().collect();
    class_like_tokens.sort();

    Ok(StringPool {
        package_uri_count: packages.len(),
        dart_uri_count: darts.len(),
        class_like_token_count: tokens.len(),
        package_uris,
        dart_uris,
        class_like_tokens,
        printable_run_count: run_count,
        collection_capped,
    })
}
