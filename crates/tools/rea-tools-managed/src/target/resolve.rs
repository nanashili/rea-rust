// The I/O-driven resolution body of `parseBinaryTarget`.
// This file is `include!`d into `mod.rs`, so it shares that module's scope
// (`BinaryTargetError`, `Resolution`, `target_failure_reason`, the imported
// `Cancellation` / `serde_json` names and the submodules).

use fs_target::{RegularFile, RegularFileState};
use header::{ExecutableExtra, ExecutableMetadata};
use pe::MzWindowsHeader;

const PREFIX_BYTES: usize = 4096;
const SHA_CHUNK_BYTES: usize = 64 * 1024;
const XML_PLIST_PROBE_CHUNK_BYTES: usize = 64 * 1024;

/// Checked positioned read returning exactly the observed byte count, mirroring
/// `handle.read(buffer, 0, length, position)`.
fn read_at(handle: &RegularFile, length: usize, position: u64) -> Result<Vec<u8>, FsError> {
    let mut buffer = vec![0u8; length];
    let observed = handle.read_at(&mut buffer, position)?;
    buffer.truncate(observed);
    Ok(buffer)
}

/// `true` when the signal is set; the caller returns `Resolution::Cancelled`.
fn cancelled(cancellation: &Cancellation) -> bool {
    cancellation.reason().is_some()
}

/// Classify a filesystem failure while reading a previously selected target
/// (TS `classifyBinaryTargetFilesystemFailure`).
fn classify_filesystem_failure(path: &str, error: &FsError) -> BinaryTargetError {
    let reason = target_failure_reason(error.code, &error.message);
    BinaryTargetError::new(path, reason).with_permission_cause(Some(error.code))
}

macro_rules! bail_cancelled {
    ($cancellation:expr) => {
        if cancelled($cancellation) {
            return Resolution::Cancelled;
        }
    };
}

/// Map a filesystem error on the selected path to a resolution, or cancellation
/// when the signal fired first (the TS catch checks cancellation before
/// classifying).
macro_rules! fs_try {
    ($expr:expr, $path:expr, $cancellation:expr) => {
        match $expr {
            Ok(value) => value,
            Err(error) => {
                if cancelled($cancellation) {
                    return Resolution::Cancelled;
                }
                return Resolution::Rejected(classify_filesystem_failure($path, &error));
            }
        }
    };
}

fn resolve_body(
    _input: &str,
    candidate: &str,
    options: &TargetOptions,
    cancellation: &Cancellation,
) -> Resolution {
    let host = host_architecture();

    bail_cancelled!(cancellation);
    // access(candidate, R_OK)
    fs_try!(fs_target::access_read(candidate), candidate, cancellation);
    bail_cancelled!(cancellation);
    // realpath(candidate)
    let canonical = fs_try!(fs_target::realpath(candidate), candidate, cancellation);
    // Windows admits the caller-selected reparse components.
    let source_path = if cfg!(windows) {
        candidate.to_string()
    } else {
        canonical.clone()
    };
    bail_cancelled!(cancellation);

    // resolveAppBundle(canonical)
    let resolved = match resolve_app_bundle(&canonical) {
        Ok(resolved) => resolved,
        Err(resolution) => return resolution,
    };
    bail_cancelled!(cancellation);
    let path = resolved.executable;
    let bundle_info_plist = resolved.info_plist;

    // openRegularFile(path, { symlinks: "reject" })
    let handle = fs_try!(
        fs_target::open_regular_file_reject(&path),
        &path,
        cancellation
    );

    let resolution = resolve_opened(
        &handle,
        &path,
        &source_path,
        bundle_info_plist.as_deref(),
        host,
        options,
        cancellation,
    );
    // handle.close() is implicit when `handle` drops.
    resolution
}

/// TS `resolveAppBundle(canonical)`.
struct ResolvedBundle {
    executable: String,
    info_plist: Option<String>,
}

fn resolve_app_bundle(path: &str) -> Result<ResolvedBundle, Resolution> {
    // stat(path)
    let metadata = match fs_target::stat(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(Resolution::Rejected(classify_filesystem_failure(
                path, &error,
            )));
        }
    };
    if !metadata.is_directory {
        return Ok(ResolvedBundle {
            executable: path.to_string(),
            info_plist: None,
        });
    }
    // extname(path).toLowerCase() !== ".app"
    if !has_app_extension(path) {
        return Err(Resolution::Rejected(
            BinaryTargetError::new(path, "this opening route requires a file or app bundle")
                .with_constraint("directory_requires_file"),
        ));
    }
    match appbundle::resolve_app_bundle_executable(path) {
        Ok(resolved) => Ok(ResolvedBundle {
            executable: resolved.executable,
            info_plist: resolved.info_plist,
        }),
        Err(error) => Err(Resolution::Rejected(error)),
    }
}

/// TS `extname(path).toLowerCase() === ".app"`.
fn has_app_extension(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match name.rfind('.') {
        // A leading dot is not an extension (Node `extname`).
        Some(0) => false,
        Some(index) => name[index..].eq_ignore_ascii_case(".app"),
        None => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_opened(
    handle: &RegularFile,
    path: &str,
    source_path: &str,
    bundle_info_plist: Option<&str>,
    host: &str,
    options: &TargetOptions,
    cancellation: &Cancellation,
) -> Resolution {
    bail_cancelled!(cancellation);
    // handle.stat()
    let metadata = fs_try!(handle.stat(), path, cancellation);
    bail_cancelled!(cancellation);

    let target_kind = options.target_kind.as_deref();
    let format_hint = options.format_hint.as_deref();
    let has_architecture = options.architecture.is_some();
    let has_entry = options.entry_point.is_some();

    if format_hint == Some("raw-binary") {
        if target_kind.is_some() && target_kind != Some("executable") {
            return Resolution::Rejected(
                BinaryTargetError::new(path, "raw-binary format requires an executable target kind")
                    .with_constraint("load_selection_rejected"),
            );
        }
        let admitted = raw::admit_raw_binary(
            options.architecture.as_deref(),
            options.entry_point.as_deref(),
            metadata.size,
        );
        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(rejection) => {
                return Resolution::Rejected(
                    BinaryTargetError::new(path, rejection.reason)
                        .with_constraint(rejection.constraint),
                );
            }
        };
        let sha = match sha256_handle(handle, path, &metadata, cancellation) {
            ShaResult::Ok(sha) => sha,
            ShaResult::Rejected(error) => return Resolution::Rejected(error),
            ShaResult::Cancelled => return Resolution::Cancelled,
        };
        let mut metadata_map = Map::new();
        metadata_map.insert(
            "entryPoint".into(),
            Value::String(admitted.entry_point.clone()),
        );
        metadata_map.insert(
            "entryPointSource".into(),
            Value::String(admitted.entry_point_source),
        );
        return Resolution::Ok(Box::new(rea_analysis::BinaryTarget {
            path: path.to_string(),
            source_path: Some(source_path.to_string()),
            sha256: sha,
            kind: "executable".into(),
            format: "raw-binary".into(),
            architecture: Some(admitted.architecture.to_string()),
            available_architectures: vec![admitted.architecture.to_string()],
            metadata: metadata_map,
        }));
    }

    // rawBinarySelectionError
    if let Some(pairing) = raw::raw_binary_selection_error(format_hint, has_architecture, has_entry)
    {
        return Resolution::Rejected(
            BinaryTargetError::new(path, pairing).with_constraint("load_selection_rejected"),
        );
    }

    if format_hint == Some("dos-com") {
        if target_kind.is_some() && target_kind != Some("executable") {
            return Resolution::Rejected(
                BinaryTargetError::new(path, "DOS COM format requires an executable target kind")
                    .with_constraint("load_selection_rejected"),
            );
        }
        if let Err(reason) = raw::validate_dos_com_length(metadata.size) {
            return Resolution::Rejected(
                BinaryTargetError::new(path, reason).with_constraint("file_format_rejected"),
            );
        }
        let sha = match sha256_handle(handle, path, &metadata, cancellation) {
            ShaResult::Ok(sha) => sha,
            ShaResult::Rejected(error) => return Resolution::Rejected(error),
            ShaResult::Cancelled => return Resolution::Cancelled,
        };
        return Resolution::Ok(Box::new(rea_analysis::BinaryTarget {
            path: path.to_string(),
            source_path: Some(source_path.to_string()),
            sha256: sha,
            kind: "executable".into(),
            format: "dos-com".into(),
            architecture: Some("x86".into()),
            available_architectures: vec!["x86".into()],
            metadata: Map::new(),
        }));
    }

    // detectArtifactFormat (skipped when an explicit database is selected).
    let artifact_format = if target_kind == Some("database") {
        None
    } else {
        match detect_artifact_format(handle, path, cancellation) {
            ArtifactResult::Format(format) => format,
            ArtifactResult::Rejected(error) => return Resolution::Rejected(error),
            ArtifactResult::Cancelled => return Resolution::Cancelled,
        }
    };

    if target_kind == Some("database")
        || (target_kind.is_none() && path.to_lowercase().ends_with(".hop"))
    {
        let sha = match sha256_handle(handle, path, &metadata, cancellation) {
            ShaResult::Ok(sha) => sha,
            ShaResult::Rejected(error) => return Resolution::Rejected(error),
            ShaResult::Cancelled => return Resolution::Cancelled,
        };
        return Resolution::Ok(Box::new(rea_analysis::BinaryTarget {
            path: path.to_string(),
            source_path: Some(source_path.to_string()),
            sha256: sha,
            kind: "database".into(),
            format: "analysis-database".into(),
            architecture: None,
            available_architectures: Vec::new(),
            metadata: Map::new(),
        }));
    }

    if let Some(format) = artifact_format {
        let sha = match sha256_handle(handle, path, &metadata, cancellation) {
            ShaResult::Ok(sha) => sha,
            ShaResult::Rejected(error) => return Resolution::Rejected(error),
            ShaResult::Cancelled => return Resolution::Cancelled,
        };
        let kind = if is_archive_format(format) {
            "archive"
        } else {
            "artifact"
        };
        return Resolution::Ok(Box::new(rea_analysis::BinaryTarget {
            path: path.to_string(),
            source_path: Some(source_path.to_string()),
            sha256: sha,
            kind: kind.into(),
            format: format.to_string(),
            architecture: None,
            available_architectures: Vec::new(),
            metadata: Map::new(),
        }));
    }

    // readExecutableMetadata(handle, host)
    let detected = match read_executable_metadata(handle, host, cancellation) {
        ExecResult::Ok(metadata) => metadata,
        ExecResult::Err(reason) => {
            return Resolution::Rejected(
                BinaryTargetError::new(path, reason).with_constraint("file_format_rejected"),
            );
        }
        ExecResult::Fs(error) => {
            if cancelled(cancellation) {
                return Resolution::Cancelled;
            }
            return Resolution::Rejected(classify_filesystem_failure(path, &error));
        }
        ExecResult::Cancelled => return Resolution::Cancelled,
    };

    let sha = match sha256_handle(handle, path, &metadata, cancellation) {
        ShaResult::Ok(sha) => sha,
        ShaResult::Rejected(error) => return Resolution::Rejected(error),
        ShaResult::Cancelled => return Resolution::Cancelled,
    };

    // Assemble: path, sourcePath, ...bundle, sha256, kind, ...detected.
    let mut metadata_map = Map::new();
    if let Some(info_plist) = bundle_info_plist {
        metadata_map.insert(
            "bundleInfoPlist".into(),
            Value::String(info_plist.to_string()),
        );
    }
    detected.insert_metadata(&mut metadata_map);

    let architecture = Some(detected.architecture.clone());
    Resolution::Ok(Box::new(rea_analysis::BinaryTarget {
        path: path.to_string(),
        source_path: Some(source_path.to_string()),
        sha256: sha,
        kind: "executable".into(),
        format: detected.format.to_string(),
        architecture,
        available_architectures: detected.available_architectures.clone(),
        metadata: metadata_map,
    }))
}

/// TS `isArchiveFormat`.
fn is_archive_format(format: &str) -> bool {
    plist_probe::is_zip_package_format(format) || matches!(format, "asar" | "dmg" | "pkg")
}

// ----- sha256Handle -----

enum ShaResult {
    Ok(String),
    Rejected(BinaryTargetError),
    Cancelled,
}

/// TS `sha256Handle(handle, path, initial, signal)`.
fn sha256_handle(
    handle: &RegularFile,
    path: &str,
    initial: &RegularFileState,
    cancellation: &Cancellation,
) -> ShaResult {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut position: u64 = 0;
    loop {
        if cancelled(cancellation) {
            return ShaResult::Cancelled;
        }
        // Math.min(chunk.length, initial.size - position + 1)
        let remaining = initial.size.saturating_sub(position) + 1;
        let length = std::cmp::min(SHA_CHUNK_BYTES as u64, remaining) as usize;
        let chunk = match read_at(handle, length, position) {
            Ok(chunk) => chunk,
            Err(error) => {
                if cancelled(cancellation) {
                    return ShaResult::Cancelled;
                }
                return ShaResult::Rejected(classify_filesystem_failure(path, &error));
            }
        };
        if cancelled(cancellation) {
            return ShaResult::Cancelled;
        }
        if chunk.is_empty() {
            break;
        }
        hash.update(&chunk);
        position += chunk.len() as u64;
        if position > initial.size {
            return ShaResult::Rejected(BinaryTargetError::new(
                path,
                "target grew while being read",
            ));
        }
    }
    if cancelled(cancellation) {
        return ShaResult::Cancelled;
    }
    // Promise.all([handle.stat(), lstat(path)])
    let opened = match handle.stat() {
        Ok(state) => state,
        Err(error) => {
            if cancelled(cancellation) {
                return ShaResult::Cancelled;
            }
            return ShaResult::Rejected(classify_filesystem_failure(path, &error));
        }
    };
    let current = match fs_target::lstat(path) {
        Ok(result) => result.state,
        Err(error) => {
            if cancelled(cancellation) {
                return ShaResult::Cancelled;
            }
            return ShaResult::Rejected(classify_filesystem_failure(path, &error));
        }
    };
    if !fs_target::same_regular_file_state(initial, &opened)
        || !fs_target::same_regular_file_state(initial, &current)
        || position != initial.size
    {
        return ShaResult::Rejected(BinaryTargetError::new(
            path,
            "target changed while being read",
        ));
    }
    let digest = hash.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    ShaResult::Ok(hex)
}

// ----- detectArtifactFormat -----

enum ArtifactResult {
    Format(Option<&'static str>),
    Rejected(BinaryTargetError),
    Cancelled,
}

fn detect_artifact_format(
    handle: &RegularFile,
    path: &str,
    cancellation: &Cancellation,
) -> ArtifactResult {
    macro_rules! fs_or {
        ($expr:expr) => {
            match $expr {
                Ok(value) => value,
                Err(error) => {
                    if cancelled(cancellation) {
                        return ArtifactResult::Cancelled;
                    }
                    return ArtifactResult::Rejected(classify_filesystem_failure(path, &error));
                }
            }
        };
    }
    if cancelled(cancellation) {
        return ArtifactResult::Cancelled;
    }
    let lower = path.to_lowercase();
    let magic = fs_or!(read_at(handle, 4096, 0));
    if cancelled(cancellation) {
        return ArtifactResult::Cancelled;
    }
    // WASM v1
    if magic.len() >= 8 && magic[0..8] == [0, 0x61, 0x73, 0x6d, 1, 0, 0, 0] {
        return ArtifactResult::Rejected(
            BinaryTargetError::new(
                path,
                "WebAssembly v1 artifacts are not supported by the native opening route",
            )
            .with_constraint("wasm_requires_static_inspection"),
        );
    }
    if plist_probe::has_zip_signature(&magic) {
        if lower.ends_with(".app") {
            return ArtifactResult::Format(Some("app-pack"));
        }
        return ArtifactResult::Format(Some(
            plist_probe::zip_package_format_for_path(&lower).unwrap_or("zip"),
        ));
    }
    if plist_probe::has_binary_plist_signature(&magic) {
        return ArtifactResult::Format(Some("plist"));
    }
    if let Some(named) = named_artifact_format(&lower) {
        return ArtifactResult::Format(Some(named));
    }
    if lower.ends_with(".pkg") && magic.len() >= 4 && &magic[0..4] == b"xar!" {
        return ArtifactResult::Format(Some("pkg"));
    }
    if lower.ends_with(".dmg") {
        if cancelled(cancellation) {
            return ArtifactResult::Cancelled;
        }
        let size = fs_or!(handle.stat()).size;
        if cancelled(cancellation) {
            return ArtifactResult::Cancelled;
        }
        if size >= 512 {
            let trailer = fs_or!(read_at(handle, 4, size - 512));
            if cancelled(cancellation) {
                return ArtifactResult::Cancelled;
            }
            if trailer.len() == 4 && trailer == b"koly" {
                return ArtifactResult::Format(Some("dmg"));
            }
        }
    }

    // XML plist prolog probe (bounded to 1 MiB).
    let mut probe = plist_probe::XmlPlistSignatureProbe::new();
    let mut state = probe.write(&magic);
    if state == plist_probe::XmlPlistProbeState::Matched {
        return ArtifactResult::Format(Some("plist"));
    }
    let mut bytes_read = magic.len();
    while state == plist_probe::XmlPlistProbeState::Pending
        && bytes_read < plist_probe::MAX_XML_PLIST_PROBE_BYTES
    {
        if cancelled(cancellation) {
            return ArtifactResult::Cancelled;
        }
        let length = std::cmp::min(
            XML_PLIST_PROBE_CHUNK_BYTES,
            plist_probe::MAX_XML_PLIST_PROBE_BYTES - bytes_read,
        );
        let chunk = fs_or!(read_at(handle, length, bytes_read as u64));
        if cancelled(cancellation) {
            return ArtifactResult::Cancelled;
        }
        if chunk.is_empty() {
            break;
        }
        bytes_read += chunk.len();
        state = probe.write(&chunk);
        if state == plist_probe::XmlPlistProbeState::Matched {
            return ArtifactResult::Format(Some("plist"));
        }
    }
    if bytes_read == plist_probe::MAX_XML_PLIST_PROBE_BYTES {
        let size = fs_or!(handle.stat()).size;
        if cancelled(cancellation) {
            return ArtifactResult::Cancelled;
        }
        if size > bytes_read as u64 {
            return ArtifactResult::Rejected(
                BinaryTargetError::new(
                    path,
                    "XML plist prolog was not found within the 1 MiB format probe limit",
                )
                .with_constraint("file_format_rejected"),
            );
        }
    }
    ArtifactResult::Format(None)
}

/// TS `namedArtifactFormat(lowerPath)`.
fn named_artifact_format(lower: &str) -> Option<&'static str> {
    if lower.ends_with(".asar") {
        return Some("asar");
    }
    if lower.ends_with(".plist") {
        return Some("plist");
    }
    if lower.ends_with(".map") {
        return Some("source-map");
    }
    // /\.(?:m?js|cjs)$/u
    if lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs") {
        return Some("javascript");
    }
    None
}

// ----- readExecutableMetadata / readPeMetadata / MIPS -----

enum ExecResult {
    Ok(ExecutableMetadata),
    Err(String),
    Fs(FsError),
    Cancelled,
}

macro_rules! exec_fs {
    ($expr:expr, $cancellation:expr) => {
        match $expr {
            Ok(value) => value,
            Err(error) => {
                if cancelled($cancellation) {
                    return ExecResult::Cancelled;
                }
                return ExecResult::Fs(error);
            }
        }
    };
}

fn read_executable_metadata(
    handle: &RegularFile,
    host: &str,
    cancellation: &Cancellation,
) -> ExecResult {
    if cancelled(cancellation) {
        return ExecResult::Cancelled;
    }
    let prefix = exec_fs!(read_at(handle, PREFIX_BYTES, 0), cancellation);
    if cancelled(cancellation) {
        return ExecResult::Cancelled;
    }
    let bytes = prefix;
    let file_size = exec_fs!(handle.stat(), cancellation).size;
    if cancelled(cancellation) {
        return ExecResult::Cancelled;
    }

    if bytes.len() >= 2 && bytes[0] == 0x4d && bytes[1] == 0x5a {
        let mut windows_header = pe::observe_mz_windows_header(&bytes, file_size, None);
        let mut signature_bytes: Option<Vec<u8>> = None;
        if let MzWindowsHeader::SignatureNeeded { offset } = windows_header {
            let length = std::cmp::min(4u64, file_size - offset) as usize;
            let signature = exec_fs!(read_at(handle, length, offset), cancellation);
            if cancelled(cancellation) {
                return ExecResult::Cancelled;
            }
            signature_bytes = Some(signature);
            windows_header =
                pe::observe_mz_windows_header(&bytes, file_size, signature_bytes.as_deref());
        }
        if let MzWindowsHeader::Declared { offset, .. } = windows_header {
            if offset < 64 {
                return ExecResult::Err("invalid Windows new-header offset in MZ image".into());
            }
            return read_pe_metadata(handle, offset, &bytes, file_size, cancellation);
        }
        // MZ relocation table re-read.
        let table_end = if bytes.len() >= 28 {
            header::read_u16_le(&bytes, 24) as u64 + header::read_u16_le(&bytes, 6) as u64 * 4
        } else {
            0
        };
        let header_bytes = if bytes.len() >= 28 {
            header::read_u16_le(&bytes, 8) as u64 * 16
        } else {
            0
        };
        if table_end > bytes.len() as u64 && table_end <= header_bytes && table_end <= file_size {
            let table = exec_fs!(read_at(handle, table_end as usize, 0), cancellation);
            if cancelled(cancellation) {
                return ExecResult::Cancelled;
            }
            return match header::parse_executable_header(&table, host, file_size, None) {
                Ok(metadata) => ExecResult::Ok(metadata),
                Err(reason) => ExecResult::Err(reason),
            };
        }
        return match header::parse_executable_header(
            &bytes,
            host,
            file_size,
            signature_bytes.as_deref(),
        ) {
            Ok(metadata) => ExecResult::Ok(metadata),
            Err(reason) => ExecResult::Err(reason),
        };
    }

    if bytes.len() >= 8 {
        let magic = header::read_u32_be(&bytes, 0);
        if magic == 0xcafebabf || magic == 0xbfbafeca {
            let little = magic == 0xbfbafeca;
            let count = header::read_u32(&bytes, 4, little);
            let required = 8 + count as usize * 32;
            if count <= 128 && required > bytes.len() {
                let header_buf = exec_fs!(read_at(handle, required, 0), cancellation);
                if cancelled(cancellation) {
                    return ExecResult::Cancelled;
                }
                return match header::parse_executable_header(&header_buf, host, file_size, None) {
                    Ok(metadata) => ExecResult::Ok(metadata),
                    Err(reason) => ExecResult::Err(reason),
                };
            }
        }
    }

    let parsed = match header::parse_executable_header(&bytes, host, file_size, None) {
        Ok(metadata) => metadata,
        Err(reason) => return ExecResult::Err(reason),
    };
    // MIPS ELF32 metadata enrichment.
    let elf_mips = matches!(
        &parsed.extra,
        ExecutableExtra::ElfFamily { key: "mips", .. }
    ) && parsed.architecture == "mips";
    let mips_base = match &parsed.extra {
        ExecutableExtra::ElfFamily { key: "mips", value } if elf_mips => {
            elf_class32_mips_base(value)
        }
        _ => None,
    };
    let mips_base = match mips_base {
        Some(base) => base,
        None => return ExecResult::Ok(parsed),
    };

    let reader = MipsRangeReader {
        handle,
        file_size,
        cancellation,
    };
    let inspection = match mips::read_mips_elf_metadata(&reader, mips_base) {
        Ok(inspection) => inspection,
        Err(reason) => {
            if reason == CANCELLED_SENTINEL {
                return ExecResult::Cancelled;
            }
            return ExecResult::Err(reason);
        }
    };

    // Merge into the mips family object preserving TS insertion order.
    let base_family = match &parsed.extra {
        ExecutableExtra::ElfFamily { value, .. } => value.clone(),
        _ => Value::Null,
    };
    let mut family = Map::new();
    if let Value::Object(object) = base_family {
        for (key, value) in object {
            family.insert(key, value);
        }
    }
    family.insert("abiFlags".into(), inspection.abi_flags);
    family.insert("gnuAttributes".into(), inspection.gnu_attributes);
    if let Some(shared_load) = inspection.shared_load {
        family.insert("sharedLoad".into(), shared_load);
    }
    if !inspection.limitations.is_empty() {
        family.insert(
            "limitations".into(),
            Value::Array(
                inspection
                    .limitations
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    ExecResult::Ok(ExecutableMetadata {
        format: parsed.format,
        architecture: parsed.architecture,
        available_architectures: parsed.available_architectures,
        extra: ExecutableExtra::ElfFamily {
            key: "mips",
            value: Value::Object(family),
        },
    })
}

/// Extract a `MipsBase` from the parsed ELF32 MIPS family object, returning None
/// unless `elfClass === 32` (the TS guard `parsed.value.mips.elfClass !== 32`).
fn elf_class32_mips_base(value: &Value) -> Option<mips::MipsBase> {
    let object = value.as_object()?;
    let elf_class = object.get("elfClass")?.as_u64()?;
    if elf_class != 32 {
        return None;
    }
    let byte_order = object.get("byteOrder")?.as_str()?;
    let elf_type = object.get("type")?.as_u64()? as u16;
    let flags = object.get("flags")?.as_u64()? as u32;
    Some(mips::MipsBase {
        elf_class: 32,
        little_endian: byte_order == "little",
        elf_type,
        flags,
    })
}

const CANCELLED_SENTINEL: &str = "\u{0}resolve_binary_target-cancelled";

struct MipsRangeReader<'a> {
    handle: &'a RegularFile,
    file_size: u64,
    cancellation: &'a Cancellation,
}

impl<'a> mips::RangeReader for MipsRangeReader<'a> {
    fn file_size(&self) -> u64 {
        self.file_size
    }

    fn check_cancelled(&self) -> Result<(), String> {
        if cancelled(self.cancellation) {
            Err(CANCELLED_SENTINEL.to_string())
        } else {
            Ok(())
        }
    }

    fn read(&self, offset: u64, length: u64, label: &str) -> Result<Vec<u8>, String> {
        self.check_cancelled()?;
        // TS: offset > fileSize - length  (and non-negative bounds)
        if self.file_size < length || offset > self.file_size - length {
            return Err(format!("MIPS {label} lies outside the file"));
        }
        let mut bytes = vec![0u8; length as usize];
        let mut total: usize = 0;
        while (total as u64) < length {
            self.check_cancelled()?;
            let observed = self
                .handle
                .read_at(&mut bytes[total..], offset + total as u64)
                .map_err(|_| format!("truncated MIPS {label}"))?;
            self.check_cancelled()?;
            if observed == 0 {
                return Err(format!("truncated MIPS {label}"));
            }
            total += observed;
        }
        Ok(bytes)
    }
}

fn read_pe_metadata(
    handle: &RegularFile,
    offset: u64,
    mz_prefix: &[u8],
    file_size: u64,
    cancellation: &Cancellation,
) -> ExecResult {
    if cancelled(cancellation) {
        return ExecResult::Cancelled;
    }
    let file_header = exec_fs!(read_at(handle, 24, offset), cancellation);
    if cancelled(cancellation) {
        return ExecResult::Cancelled;
    }
    if file_header.len() != 24 {
        return ExecResult::Err("invalid or truncated PE header".into());
    }
    let windows_header =
        pe::observe_mz_windows_header(mz_prefix, file_size, Some(&file_header[0..4]));
    let signature = match windows_header {
        MzWindowsHeader::Declared { signature, .. } => signature,
        _ => {
            return ExecResult::Err("invalid Windows new-header signature in MZ image".into());
        }
    };
    match signature {
        pe::MzSignature::Ne => return ExecResult::Err("unsupported NE executable in MZ image".into()),
        pe::MzSignature::Le => return ExecResult::Err("unsupported LE executable in MZ image".into()),
        pe::MzSignature::Lx => return ExecResult::Err("unsupported LX executable in MZ image".into()),
        _ => {}
    }
    let optional_header_size = header::read_u16_le(&file_header, 20) as usize;
    if optional_header_size > 4096 {
        return ExecResult::Err("invalid PE optional header size".into());
    }
    let number_of_sections = header::read_u16_le(&file_header, 6) as u32;
    let record = exec_fs!(read_at(handle, 24 + optional_header_size, offset), cancellation);
    if cancelled(cancellation) {
        return ExecResult::Cancelled;
    }
    if record.len() != 24 + optional_header_size {
        return ExecResult::Err("invalid or truncated PE header".into());
    }
    let code_view = match read_pe_code_view(
        handle,
        offset,
        number_of_sections,
        &record[24..],
        optional_header_size,
        cancellation,
    ) {
        CodeViewResult::Ok(value) => value,
        CodeViewResult::Fs(error) => {
            if cancelled(cancellation) {
                return ExecResult::Cancelled;
            }
            return ExecResult::Fs(error);
        }
        CodeViewResult::Cancelled => return ExecResult::Cancelled,
    };
    match pe::parse_pe_record(&record, code_view) {
        Ok(metadata) => ExecResult::Ok(metadata),
        Err(reason) => ExecResult::Err(reason),
    }
}

enum CodeViewResult {
    Ok(Option<Value>),
    Fs(FsError),
    Cancelled,
}

macro_rules! cv_fs {
    ($expr:expr, $cancellation:expr) => {
        match $expr {
            Ok(value) => value,
            Err(error) => {
                if cancelled($cancellation) {
                    return CodeViewResult::Cancelled;
                }
                return CodeViewResult::Fs(error);
            }
        }
    };
}

fn read_pe_code_view(
    handle: &RegularFile,
    pe_offset: u64,
    number_of_sections: u32,
    optional_header: &[u8],
    optional_header_size: usize,
    cancellation: &Cancellation,
) -> CodeViewResult {
    if cancelled(cancellation) {
        return CodeViewResult::Cancelled;
    }
    let debug_dir = match pe::pe_debug_directory_entry(optional_header) {
        Some(debug_dir) => debug_dir,
        None => return CodeViewResult::Ok(None),
    };
    if number_of_sections > 96 {
        return CodeViewResult::Ok(None);
    }
    let section_table_offset = pe_offset + 24 + optional_header_size as u64;
    let section_table_size = number_of_sections as usize * 40;
    let section_table = cv_fs!(
        read_at(handle, section_table_size, section_table_offset),
        cancellation
    );
    if cancelled(cancellation) {
        return CodeViewResult::Cancelled;
    }
    if section_table.len() != section_table_size {
        return CodeViewResult::Ok(None);
    }
    let debug_file_offset = match pe::pe_rva_to_file_offset(
        debug_dir.debug_rva,
        &section_table,
        number_of_sections,
        debug_dir.size_of_headers,
        std::cmp::min(debug_dir.debug_size, 4096),
    ) {
        Some(offset) => offset,
        None => return CodeViewResult::Ok(None),
    };
    let max_debug_size = std::cmp::min(debug_dir.debug_size, 4096) as usize;
    let debug_directory_buffer = cv_fs!(
        read_at(handle, max_debug_size, debug_file_offset as u64),
        cancellation
    );
    if cancelled(cancellation) {
        return CodeViewResult::Cancelled;
    }
    let num_entries = debug_directory_buffer.len() / 28;
    for j in 0..num_entries {
        let entry_offset = j * 28;
        let entry_type = header::read_u32_le(&debug_directory_buffer, entry_offset + 12);
        if entry_type != 2 {
            continue;
        }
        let size_of_data = header::read_u32_le(&debug_directory_buffer, entry_offset + 16);
        let mut pointer_to_raw_data =
            header::read_u32_le(&debug_directory_buffer, entry_offset + 24);
        if pointer_to_raw_data == 0 {
            let address_of_raw_data =
                header::read_u32_le(&debug_directory_buffer, entry_offset + 20);
            let mapped = pe::pe_rva_to_file_offset(
                address_of_raw_data,
                &section_table,
                number_of_sections,
                debug_dir.size_of_headers,
                std::cmp::min(size_of_data, 4096),
            );
            match mapped {
                Some(mapped) => pointer_to_raw_data = mapped,
                None => continue,
            }
        }
        if size_of_data < 16 {
            continue;
        }
        let max_code_view_read = std::cmp::min(size_of_data, 4096) as usize;
        let code_view_buffer = cv_fs!(
            read_at(handle, max_code_view_read, pointer_to_raw_data as u64),
            cancellation
        );
        if cancelled(cancellation) {
            return CodeViewResult::Cancelled;
        }
        if let Some(parsed) = pe::parse_code_view_data(&code_view_buffer, size_of_data) {
            return CodeViewResult::Ok(Some(parsed));
        }
    }
    CodeViewResult::Ok(None)
}
