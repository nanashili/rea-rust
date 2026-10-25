//! Read-only Dart AOT snapshot inspection from a caller-selected APK.
//!
//! The reader deliberately treats snapshot strings as byte-pattern evidence.
//! It does not deserialize Dart clusters, execute an engine, or infer package
//! structure from anything other than printable runs in the isolate data.

use flate2::read::DeflateDecoder;
use rea_core::{
    cancellation::Cancellation,
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure},
};
use rea_host::fs::stable_file;
#[cfg(unix)]
use rea_host::fs::unix_file::UnixFiles;
#[cfg(windows)]
use rea_host::fs::windows_file::WindowsFiles;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
    path::Path,
    sync::Arc,
};

pub const OPERATION: &str = "inspect_dart_aot";
const MAX_APK_BYTES: usize = 1024 * 1024 * 1024;
const MAX_LIBRARY_BYTES: usize = 256 * 1024 * 1024;
const MAX_POOL_URIS: usize = 500;
const MAX_POOL_TOKENS: usize = 2_000;
const MAX_RUN_BYTES: usize = 1024;
const COLLECTION_SLACK: usize = 2;
const SYMBOLS: [&str; 4] = [
    "_kDartVmSnapshotData",
    "_kDartVmSnapshotInstructions",
    "_kDartIsolateSnapshotData",
    "_kDartIsolateSnapshotInstructions",
];
const ABI_PREFERENCE: [&str; 4] = ["arm64-v8a", "x86_64", "x86", "armeabi-v7a"];

#[derive(Debug, Serialize)]
struct Section {
    name: String,
    offset: usize,
    size: usize,
    magic_valid: bool,
    kind: Option<u64>,
    header_length: Option<u64>,
}
#[derive(Debug, Serialize)]
struct Pool {
    coverage: String,
    package_uris: Vec<String>,
    package_uri_count_at_least: usize,
    dart_uris: Vec<String>,
    dart_uri_count_at_least: usize,
    class_like_tokens: Vec<String>,
    class_like_token_count_at_least: usize,
    printable_run_count: usize,
}
#[derive(Debug, Serialize)]
struct Report {
    target: Target,
    abi: String,
    libapp: LibApp,
    string_pool: Pool,
    coverage: String,
}
#[derive(Debug, Serialize)]
struct Target {
    path: String,
    bytes: usize,
    sha256: String,
}
#[derive(Debug, Serialize)]
struct LibApp {
    coverage: String,
    bytes: usize,
    sha256: String,
    snapshot_hash: Option<String>,
    snapshot_hash_candidates: Vec<String>,
    snapshot_hash_sources: usize,
    sections: Vec<Section>,
}

#[derive(Clone)]
struct Entry {
    name: String,
    method: u16,
    compressed: Vec<u8>,
    uncompressed_size: usize,
}

pub fn inspect(
    input: &Value,
    cancellation: &Cancellation,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("path", "Expected an absolute APK path"))?;
    if path.is_empty() || !Path::new(path).is_absolute() || path.contains('\0') {
        return Err(invalid("path", "Expected an absolute APK path"));
    }
    let requested_abi = object.get("abi").and_then(Value::as_str);
    if let Some(abi) = requested_abi {
        if abi.is_empty() || abi.contains('/') {
            return Err(invalid(
                "abi",
                "ABI must be a non-empty lib directory label",
            ));
        }
    }
    if let Some(detail) = object.get("detail") {
        if !matches!(detail.as_str(), Some("complete") | Some("summary")) {
            return Err(invalid("detail", "Expected complete or summary"));
        }
    }
    ensure_active(cancellation)?;
    let snapshot = stable_file::read(
        Arc::new(platform_files()),
        Path::new(path),
        MAX_APK_BYTES,
        cancellation,
    )
    .map_err(|_| invalid("path", "Unable to read a stable regular APK file"))?;
    let entries = zip_entries(&snapshot.bytes).map_err(|reason| invalid("path", &reason))?;
    let mut candidates = entries
        .iter()
        .filter_map(|entry| {
            entry
                .name
                .strip_prefix("lib/")
                .and_then(|tail| tail.strip_suffix("/libapp.so"))
                .map(|abi| (abi.to_string(), entry.clone()))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        abi_rank(&left.0)
            .cmp(&abi_rank(&right.0))
            .then_with(|| left.0.cmp(&right.0))
    });
    let selected = requested_abi
        .and_then(|abi| candidates.iter().find(|(name, _)| name == abi).cloned())
        .or_else(|| candidates.first().cloned())
        .ok_or_else(|| invalid("abi", "No lib/<abi>/libapp.so was found in the APK"))?;
    if requested_abi.is_some() && selected.0 != requested_abi.unwrap() {
        return Err(invalid(
            "abi",
            "No libapp.so was found for the requested ABI",
        ));
    }
    if selected.1.uncompressed_size > MAX_LIBRARY_BYTES {
        return Err(resource("libapp.so exceeds the 256 MiB read budget"));
    }
    let image = inflate_entry(&selected.1).map_err(|reason| invalid("path", &reason))?;
    ensure_active(cancellation)?;
    let image_sha = sha256(&image);
    let parsed = parse_elf(&image);
    let mut sections = Vec::new();
    let mut isolate_data: Option<&[u8]> = None;
    let mut hashes = BTreeSet::new();
    let mut hash_sources = 0usize;
    let mut failures = Vec::new();
    for name in SYMBOLS {
        match parsed.symbols.get(name) {
            Some(&(offset, size))
                if offset <= image.len() && size <= image.len().saturating_sub(offset) =>
            {
                let data = &image[offset..offset + size];
                let header = if name.ends_with("Data") {
                    snapshot_header(data)
                } else {
                    None
                };
                if let Some((valid, kind, length, hash, complete)) = header {
                    if let Some(hash) = hash {
                        hashes.insert(hash);
                        hash_sources += 1;
                    }
                    sections.push(Section {
                        name: name.into(),
                        offset,
                        size,
                        magic_valid: valid,
                        kind,
                        header_length: length,
                    });
                    if name == "_kDartIsolateSnapshotData" {
                        isolate_data = Some(data);
                    }
                    if !complete {
                        failures.push(format!(
                            "{name} has an incomplete or invalid snapshot header"
                        ));
                    }
                } else {
                    sections.push(Section {
                        name: name.into(),
                        offset,
                        size,
                        magic_valid: false,
                        kind: None,
                        header_length: None,
                    });
                    if name == "_kDartIsolateSnapshotData" {
                        isolate_data = Some(data);
                    }
                    failures.push(format!("{name} has an unreadable snapshot header"));
                }
            }
            Some(_) => failures.push(format!("{name} symbol range is outside the ELF image")),
            None => failures.push(format!("{name} was not found in the ELF symbol table")),
        }
    }
    let pool = project_pool(isolate_data.unwrap_or(&[]));
    let snapshot_partial =
        failures.len() > 0 || sections.len() < 4 || hashes.len() != 1 || hash_sources != 2;
    let pool_partial = pool.capped
        || pool.package_count > MAX_POOL_URIS
        || pool.dart_count > MAX_POOL_URIS
        || pool.token_count > MAX_POOL_TOKENS;
    let report = Report {
        target: Target {
            path: path.into(),
            bytes: snapshot.bytes.len(),
            sha256: snapshot.sha256.clone(),
        },
        abi: selected.0,
        libapp: LibApp {
            coverage: if snapshot_partial {
                "partial".into()
            } else {
                "complete".into()
            },
            bytes: image.len(),
            sha256: image_sha,
            snapshot_hash: (hashes.len() == 1).then(|| hashes.iter().next().unwrap().clone()),
            snapshot_hash_candidates: hashes.into_iter().collect(),
            snapshot_hash_sources: hash_sources,
            sections,
        },
        string_pool: Pool {
            coverage: if pool_partial {
                "partial".into()
            } else {
                "complete".into()
            },
            package_uris: pool.packages.into_iter().take(MAX_POOL_URIS).collect(),
            package_uri_count_at_least: pool.package_count,
            dart_uris: pool.darts.into_iter().take(MAX_POOL_URIS).collect(),
            dart_uri_count_at_least: pool.dart_count,
            class_like_tokens: pool.tokens.into_iter().take(MAX_POOL_TOKENS).collect(),
            class_like_token_count_at_least: pool.token_count,
            printable_run_count: pool.runs,
        },
        coverage: if snapshot_partial || pool_partial {
            "partial".into()
        } else {
            "complete".into()
        },
    };
    let mut limitations = vec!["Snapshot sections are located through the ELF symbol table; payloads without exported symbols remain unresolved.".into(), "String-pool entries are printable byte-pattern observations, not deserialized Dart cluster semantics.".into(), "No engine or target execution was performed.".into()];
    limitations.extend(failures);
    let subject = Subject::new(
        path,
        snapshot.sha256.clone(),
        NativeFormat::AndroidPackage,
        None,
    )
    .map_err(|error| execution(&error.to_string()))?;
    let evidence = ArtifactEvidence::new(
        subject,
        Provider {
            id: "rust-dart-aot",
            name: "REA Rust Dart AOT reader",
            version: Some("1"),
        },
        Observation {
            operation: OPERATION,
            result: report,
            limitations: limitations.clone(),
            locations: vec![Location::ArtifactPath { path: path.into() }],
        },
    )
    .map_err(|error| execution(&error.to_string()))?;
    let raw = serde_json::to_value(evidence).map_err(|error| execution(&error.to_string()))?;
    let record = rea_core::evidence::record::EvidenceRecord::create_unsigned(
        &serde_json::value::to_raw_value(&raw).map_err(|error| execution(&error.to_string()))?,
    )
    .map_err(|error| execution(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(record.raw().get().to_owned())
            .map_err(|error| execution(&error.to_string()))?,
    )
}

#[cfg(unix)]
fn platform_files() -> UnixFiles {
    UnixFiles
}

#[cfg(windows)]
fn platform_files() -> WindowsFiles {
    WindowsFiles
}

struct PoolState {
    packages: BTreeSet<String>,
    darts: BTreeSet<String>,
    tokens: BTreeSet<String>,
    package_count: usize,
    dart_count: usize,
    token_count: usize,
    runs: usize,
    capped: bool,
}
fn project_pool(bytes: &[u8]) -> PoolState {
    let mut state = PoolState {
        packages: BTreeSet::new(),
        darts: BTreeSet::new(),
        tokens: BTreeSet::new(),
        package_count: 0,
        dart_count: 0,
        token_count: 0,
        runs: 0,
        capped: false,
    };
    let mut run = Vec::new();
    let mut overflow = false;
    let consider = |run: &[u8], state: &mut PoolState| {
        if run.len() < 5 {
            return;
        }
        state.runs += 1;
        let text = String::from_utf8_lossy(run).into_owned();
        if text.starts_with("package:") {
            state.package_count += 1;
            if state.packages.len() < MAX_POOL_URIS * COLLECTION_SLACK {
                state.packages.insert(text);
            } else {
                state.capped = true;
            }
        } else if text.starts_with("dart:") {
            state.dart_count += 1;
            if state.darts.len() < MAX_POOL_URIS * COLLECTION_SLACK {
                state.darts.insert(text);
            } else {
                state.capped = true;
            }
        } else if text.len() <= 128
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'.')
        {
            state.token_count += 1;
            if state.tokens.len() < MAX_POOL_TOKENS * COLLECTION_SLACK {
                state.tokens.insert(text);
            } else {
                state.capped = true;
            }
        }
    };
    for byte in bytes {
        if (0x20..0x7f).contains(byte) {
            if run.len() < MAX_RUN_BYTES {
                run.push(*byte);
            } else {
                overflow = true;
                state.capped = true;
            }
        } else {
            if !overflow {
                consider(&run, &mut state);
            }
            run.clear();
            overflow = false;
        }
    }
    if !overflow {
        consider(&run, &mut state);
    }
    state
}

fn snapshot_header(data: &[u8]) -> Option<(bool, Option<u64>, Option<u64>, Option<String>, bool)> {
    if data.len() < 20 || u32::from_le_bytes(data[0..4].try_into().ok()?) != 0xdcdcf5f5 {
        return Some((false, None, None, None, false));
    }
    let length = u64::from_le_bytes(data[4..12].try_into().ok()?);
    let kind = u64::from_le_bytes(data[12..20].try_into().ok()?);
    let hash = (data.len() >= 52)
        .then(|| String::from_utf8_lossy(&data[20..52]).into_owned())
        .filter(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        });
    let complete = kind == 3
        && hash.is_some()
        && length >= 48
        && length <= (data.len() as u64).saturating_sub(4);
    Some((true, Some(kind), Some(length), hash, complete))
}

fn parse_elf(bytes: &[u8]) -> Elf {
    let mut symbols = BTreeMap::new();
    if bytes.len() < 52 || &bytes[..4] != b"\x7fELF" || bytes[5] != 1 {
        return Elf { symbols };
    }
    let class64 = bytes[4] == 2;
    let phoff = read_u(bytes, if class64 { 32 } else { 28 }, class64).unwrap_or(0) as usize;
    let phentsize = read_u(bytes, if class64 { 54 } else { 42 }, false).unwrap_or(0) as usize;
    let phnum = read_u(bytes, if class64 { 56 } else { 44 }, false).unwrap_or(0) as usize;
    let mut loads = Vec::new();
    for index in 0..phnum.min(4096) {
        let at = phoff.saturating_add(index.saturating_mul(phentsize));
        if at + phentsize > bytes.len() {
            break;
        }
        let typ = read_u(bytes, at, false).unwrap_or(0);
        if typ != 1 {
            continue;
        }
        let (offset, vaddr, filesz) = if class64 {
            (
                read_u(bytes, at + 8, true).unwrap_or(0),
                read_u(bytes, at + 16, true).unwrap_or(0),
                read_u(bytes, at + 32, true).unwrap_or(0),
            )
        } else {
            (
                read_u(bytes, at + 4, false).unwrap_or(0),
                read_u(bytes, at + 8, false).unwrap_or(0),
                read_u(bytes, at + 16, false).unwrap_or(0),
            )
        };
        loads.push((vaddr, offset, filesz));
    }
    let shoff = read_u(bytes, if class64 { 40 } else { 32 }, class64).unwrap_or(0) as usize;
    let shentsize = read_u(bytes, if class64 { 58 } else { 46 }, false).unwrap_or(0) as usize;
    let shnum = read_u(bytes, if class64 { 60 } else { 48 }, false).unwrap_or(0) as usize;
    if shentsize == 0 || shnum > 65536 {
        return Elf { symbols };
    }
    let mut sections = Vec::new();
    for index in 0..shnum {
        let at = shoff.saturating_add(index.saturating_mul(shentsize));
        if at + shentsize > bytes.len() {
            break;
        }
        let (typ, off, size, link, entsize) = if class64 {
            (
                read_u(bytes, at + 4, false).unwrap_or(0),
                read_u(bytes, at + 24, true).unwrap_or(0),
                read_u(bytes, at + 32, true).unwrap_or(0),
                read_u(bytes, at + 40, false).unwrap_or(0),
                read_u(bytes, at + 56, true).unwrap_or(0),
            )
        } else {
            (
                read_u(bytes, at + 4, false).unwrap_or(0),
                read_u(bytes, at + 16, false).unwrap_or(0),
                read_u(bytes, at + 20, false).unwrap_or(0),
                read_u(bytes, at + 24, false).unwrap_or(0),
                read_u(bytes, at + 36, false).unwrap_or(0),
            )
        };
        sections.push((
            typ,
            off as usize,
            size as usize,
            link as usize,
            entsize as usize,
        ));
    }
    for (_, off, size, link, entsize) in sections
        .iter()
        .copied()
        .filter(|(typ, _, _, _, _)| *typ == 2 || *typ == 11)
    {
        if link >= sections.len() || entsize == 0 || off.saturating_add(size) > bytes.len() {
            continue;
        }
        let (_, stroff, strsize, _, _) = sections[link];
        let end = stroff.saturating_add(strsize).min(bytes.len());
        if stroff >= end {
            continue;
        }
        let count = size / entsize;
        for i in 0..count {
            let at = off + i * entsize;
            let name_off = read_u(bytes, at, false).unwrap_or(u64::MAX) as usize;
            let value = read_u(bytes, at + if class64 { 8 } else { 4 }, class64).unwrap_or(0);
            let sym_size =
                read_u(bytes, at + if class64 { 16 } else { 8 }, class64).unwrap_or(0) as usize;
            if name_off >= strsize {
                continue;
            }
            let end_name = bytes[stroff + name_off..end]
                .iter()
                .position(|b| *b == 0)
                .map(|n| stroff + name_off + n)
                .unwrap_or(end);
            let Ok(name) = std::str::from_utf8(&bytes[stroff + name_off..end_name]) else {
                continue;
            };
            if !SYMBOLS.contains(&name) {
                continue;
            }
            let Some((load_vaddr, load_offset, _load_size)) = loads
                .iter()
                .find(|(base, _, size)| value >= *base && value.saturating_sub(*base) < *size)
            else {
                continue;
            };
            let offset = load_offset.saturating_add(value.saturating_sub(*load_vaddr)) as usize;
            symbols
                .entry(name.to_string())
                .or_insert((offset, sym_size));
        }
    }
    Elf { symbols }
}
struct Elf {
    symbols: BTreeMap<String, (usize, usize)>,
}
fn read_u(bytes: &[u8], offset: usize, wide: bool) -> Option<u64> {
    if wide {
        Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    } else {
        Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as u64)
    }
}

fn zip_entries(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    let start = bytes.len().saturating_sub(65_557);
    let eocd = bytes[start..]
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .map(|n| start + n)
        .ok_or("APK ZIP directory is missing")?;
    let count = u16::from_le_bytes(
        bytes[eocd + 10..eocd + 12]
            .try_into()
            .map_err(|_| "Invalid ZIP entry count")?,
    ) as usize;
    let dir_size = u32::from_le_bytes(
        bytes[eocd + 12..eocd + 16]
            .try_into()
            .map_err(|_| "Invalid ZIP directory size")?,
    ) as usize;
    let dir_off = u32::from_le_bytes(
        bytes[eocd + 16..eocd + 20]
            .try_into()
            .map_err(|_| "Invalid ZIP directory offset")?,
    ) as usize;
    if dir_off.saturating_add(dir_size) > bytes.len() {
        return Err("ZIP directory exceeds APK bounds".into());
    }
    let mut result = Vec::new();
    let mut cursor = dir_off;
    for _ in 0..count {
        if cursor + 46 > bytes.len() || &bytes[cursor..cursor + 4] != b"PK\x01\x02" {
            return Err("Malformed ZIP central directory".into());
        }
        let method = u16::from_le_bytes(bytes[cursor + 10..cursor + 12].try_into().unwrap());
        let compressed_size =
            u32::from_le_bytes(bytes[cursor + 20..cursor + 24].try_into().unwrap()) as usize;
        let uncompressed_size =
            u32::from_le_bytes(bytes[cursor + 24..cursor + 28].try_into().unwrap()) as usize;
        let name_len =
            u16::from_le_bytes(bytes[cursor + 28..cursor + 30].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(bytes[cursor + 30..cursor + 32].try_into().unwrap()) as usize;
        let comment_len =
            u16::from_le_bytes(bytes[cursor + 32..cursor + 34].try_into().unwrap()) as usize;
        let local_off =
            u32::from_le_bytes(bytes[cursor + 42..cursor + 46].try_into().unwrap()) as usize;
        let name_end = cursor + 46 + name_len;
        let name = std::str::from_utf8(
            bytes
                .get(cursor + 46..name_end)
                .ok_or("Malformed ZIP path")?,
        )
        .map_err(|_| "ZIP path is not UTF-8")?
        .to_string();
        if local_off + 30 > bytes.len() || &bytes[local_off..local_off + 4] != b"PK\x03\x04" {
            return Err("Malformed ZIP local header".into());
        }
        let local_name_len =
            u16::from_le_bytes(bytes[local_off + 26..local_off + 28].try_into().unwrap()) as usize;
        let local_extra_len =
            u16::from_le_bytes(bytes[local_off + 28..local_off + 30].try_into().unwrap()) as usize;
        let data_start = local_off + 30 + local_name_len + local_extra_len;
        let data_end = data_start.saturating_add(compressed_size);
        if data_end > bytes.len() {
            return Err("ZIP entry exceeds APK bounds".into());
        }
        result.push(Entry {
            name,
            method,
            compressed: bytes[data_start..data_end].to_vec(),
            uncompressed_size,
        });
        cursor = name_end + extra_len + comment_len;
    }
    Ok(result)
}
fn inflate_entry(entry: &Entry) -> Result<Vec<u8>, String> {
    match entry.method {
        0 => {
            if entry.compressed.len() != entry.uncompressed_size {
                return Err("Stored ZIP entry size mismatch".into());
            }
            Ok(entry.compressed.clone())
        }
        8 => {
            let mut decoder = DeflateDecoder::new(Cursor::new(&entry.compressed));
            let mut output = Vec::with_capacity(entry.uncompressed_size.min(MAX_LIBRARY_BYTES));
            decoder
                .read_to_end(&mut output)
                .map_err(|_| "Unable to inflate libapp.so".to_string())?;
            if output.len() != entry.uncompressed_size || output.len() > MAX_LIBRARY_BYTES {
                return Err("Inflated libapp.so exceeds its declared size".into());
            }
            Ok(output)
        }
        _ => Err("Unsupported ZIP compression method for libapp.so".into()),
    }
}
fn abi_rank(abi: &str) -> usize {
    ABI_PREFERENCE
        .iter()
        .position(|value| *value == abi)
        .unwrap_or(ABI_PREFERENCE.len())
}
fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    if cancellation.reason().is_some() {
        Err(cancelled())
    } else {
        Ok(())
    }
}
fn invalid(path: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("field", Detail::Text(path.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        message.into(),
        false,
        "Use a smaller APK or ABI.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn cancelled() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "The operation was cancelled before completion.".into(),
        false,
        "Retry the operation if the result is still needed.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn execution(message: &str) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        message.into(),
        true,
        "Review the artifact and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
