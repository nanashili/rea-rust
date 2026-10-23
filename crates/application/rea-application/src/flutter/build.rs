//! Bounded, offline Flutter APK identification.
//!
//! The producer reads only ZIP members under `lib/<abi>/` and never runs an
//! engine, executes Dart, or contacts a device.  Runtime adapters may wrap
//! the returned projection in the normal Evidence envelope.

use flate2::read::DeflateDecoder;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

pub const OPERATION: &str = "identify_flutter_build";
pub const MAX_APK_BYTES: usize = 2 * 1024 * 1024 * 1024;
pub const MAX_LIBRARY_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_TOTAL_EXTRACTION_BYTES: usize = 768 * 1024 * 1024;
const MAX_ABIS: usize = 32;
const MAX_HASHES: usize = 64;
const MAX_LIBRARY_PATH_BYTES: usize = 1024;
const LABEL_CARRY_BYTES: usize = 640;

/// Validate the strict caller input schema.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    if object.keys().any(|key| key != "path") {
        return Err(invalid("input contains an unknown field"));
    }
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| invalid("path must be a non-empty absolute path"))?;
    if path.contains('\0') || !Path::new(path).is_absolute() {
        return Err(invalid("path must be an absolute path"));
    }
    Ok(())
}

/// Inspect the selected APK using bounded ZIP member reads.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let path = input["path"].as_str().expect("validated path");
    let bytes = std::fs::read(path)
        .map_err(|error| provider_failure(format!("unable to read APK: {error}")))?;
    if bytes.len() > MAX_APK_BYTES {
        return Err(resource_failure("APK exceeds the 2 GiB input limit"));
    }
    let target_sha256 = digest(&bytes);
    let entries = zip_entries(&bytes)?;
    let mut libraries = BTreeMap::<String, LibraryFacts>::new();
    let mut flutter_paths = BTreeSet::new();
    let mut extracted = 0usize;
    for entry in entries {
        let Some((abi, kind)) = flutter_member(&entry.name) else {
            continue;
        };
        if !flutter_paths.insert(entry.name.clone()) {
            return Err(invalid("APK contains duplicate Flutter library members"));
        }
        if libraries.len() >= MAX_ABIS && !libraries.contains_key(abi) {
            return Err(resource_failure("Flutter ABI inventory exceeds 32 ABIs"));
        }
        if entry.uncompressed_size > MAX_LIBRARY_BYTES {
            return Err(resource_failure(
                "Flutter library exceeds the 256 MiB member limit",
            ));
        }
        extracted = extracted.saturating_add(entry.uncompressed_size);
        if extracted > MAX_TOTAL_EXTRACTION_BYTES {
            return Err(resource_failure(
                "Flutter library extraction exceeds the 768 MiB cumulative limit",
            ));
        }
        let payload = inflate_entry(&bytes, &entry)?;
        let facts = libraries.entry(abi.to_owned()).or_default();
        let hash = digest(&payload);
        if kind == "libapp" {
            let (sources, candidates, candidates_capped) = snapshot_hashes(&payload);
            facts.libapp = Some(Library {
                bytes: payload.len(),
                sha256: hash,
                sources,
                candidates,
                candidates_capped,
                elf_valid: elf_header_valid(&payload),
            });
        } else {
            let labels = labeled_strings(&payload);
            let (build_ids, build_ids_capped) = gnu_build_ids(&payload);
            facts.libflutter = Some(Engine {
                bytes: payload.len(),
                sha256: hash,
                build_id: (build_ids.len() == 1).then(|| build_ids[0].clone()),
                build_id_candidates: build_ids,
                build_ids_capped,
                dart_version: labels.dart_version,
                dart_version_capped: labels.dart_version_capped,
                toolchain: labels.toolchain,
                toolchain_capped: labels.toolchain_capped,
            });
        }
    }
    let mut abis = Vec::with_capacity(libraries.len());
    let mut partial = false;
    for (abi, facts) in libraries {
        let app = facts.libapp;
        let engine = facts.libflutter;
        let app_json = match app {
            Some(value) => {
                let snapshot_hash =
                    (value.candidates.len() == 1).then(|| value.candidates[0].clone());
                if snapshot_hash.is_none()
                    || value.sources != 2
                    || value.candidates_capped
                    || !value.elf_valid
                {
                    partial = true;
                }
                serde_json::json!({"present":true,"bytes":value.bytes,"sha256":value.sha256,"elf_header_valid":value.elf_valid,"snapshot_hash_sources":value.sources,"snapshot_hash_candidates":value.candidates,"snapshot_hash":snapshot_hash})
            }
            None => {
                serde_json::json!({"present":false,"bytes":null,"sha256":null,"elf_header_valid":null,"snapshot_hash_sources":0,"snapshot_hash_candidates":[],"snapshot_hash":null})
            }
        };
        let engine_json = match engine {
            Some(value) => {
                if value.toolchain_capped
                    || value.dart_version_capped
                    || value.build_id_candidates.is_empty()
                    || value.build_id_candidates.len() > 1
                    || value.build_ids_capped
                {
                    partial = true;
                }
                serde_json::json!({"present":true,"bytes":value.bytes,"sha256":value.sha256,"build_id":value.build_id,"build_id_candidates":value.build_id_candidates,"dart_version":value.dart_version,"dart_version_capped":value.dart_version_capped,"toolchain_lines":value.toolchain,"toolchain_capped":value.toolchain_capped})
            }
            None => {
                serde_json::json!({"present":false,"bytes":null,"sha256":null,"build_id":null,"build_id_candidates":[],"dart_version":null,"dart_version_capped":false,"toolchain_lines":[],"toolchain_capped":false})
            }
        };
        if app_json["present"] != engine_json["present"] {
            partial = true;
        }
        abis.push(serde_json::json!({"abi":abi,"libapp":app_json,"libflutter":engine_json}));
    }
    let flutter_detected = abis.iter().any(|abi| abi["libapp"]["present"] == true);
    Ok(serde_json::json!({
        "target":{"path":path,"bytes":bytes.len(),"sha256":target_sha256},
        "flutter_detected":flutter_detected,
        "abis":abis,
        "coverage":if partial {"partial"} else {"complete"}
    }))
}

#[derive(Default)]
struct LibraryFacts {
    libapp: Option<Library>,
    libflutter: Option<Engine>,
}
struct Library {
    bytes: usize,
    sha256: String,
    sources: usize,
    candidates: Vec<String>,
    candidates_capped: bool,
    elf_valid: bool,
}
struct Engine {
    bytes: usize,
    sha256: String,
    build_id: Option<String>,
    build_id_candidates: Vec<String>,
    build_ids_capped: bool,
    dart_version: Option<String>,
    dart_version_capped: bool,
    toolchain: Vec<String>,
    toolchain_capped: bool,
}
struct ZipEntry {
    name: String,
    method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
    data_offset: usize,
}

fn flutter_member(name: &str) -> Option<(&str, &str)> {
    if name.len() > MAX_LIBRARY_PATH_BYTES {
        return None;
    }

    let mut parts = name.split('/');
    if parts.next()? != "lib" {
        return None;
    }
    let abi = parts.next()?;
    let file = parts.next()?;
    if abi.is_empty() || parts.next().is_some() {
        return None;
    }
    let kind = file.strip_suffix(".so")?;
    matches!(kind, "libapp" | "libflutter").then_some((abi, kind))
}

fn zip_entries(bytes: &[u8]) -> Result<Vec<ZipEntry>, Failure> {
    let mut offset = 0usize;
    let mut entries = Vec::new();
    while offset + 30 <= bytes.len() && bytes[offset..offset + 4] == *b"PK\x03\x04" {
        let method = u16::from_le_bytes(bytes[offset + 8..offset + 10].try_into().unwrap());
        let compressed_size =
            u32::from_le_bytes(bytes[offset + 18..offset + 22].try_into().unwrap()) as usize;
        let uncompressed_size =
            u32::from_le_bytes(bytes[offset + 22..offset + 26].try_into().unwrap()) as usize;
        let name_len =
            u16::from_le_bytes(bytes[offset + 26..offset + 28].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(bytes[offset + 28..offset + 30].try_into().unwrap()) as usize;
        let name_start = offset + 30;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| invalid("ZIP member name overflows"))?;
        if name_end > bytes.len() {
            return Err(invalid("ZIP member name exceeds APK bytes"));
        }
        let data_offset = name_start
            .checked_add(name_len)
            .and_then(|value| value.checked_add(extra_len))
            .ok_or_else(|| invalid("ZIP member header overflows"))?;
        let end = data_offset
            .checked_add(compressed_size)
            .ok_or_else(|| invalid("ZIP member data overflows"))?;
        if end > bytes.len() {
            return Err(invalid("ZIP member exceeds APK bytes"));
        }
        let name = std::str::from_utf8(&bytes[name_start..name_end])
            .map_err(|_| invalid("ZIP member name is not UTF-8"))?
            .to_owned();
        entries.push(ZipEntry {
            name,
            method,
            compressed_size,
            uncompressed_size,
            data_offset,
        });
        offset = end;
    }
    if entries.is_empty() {
        return Err(invalid("APK contains no readable ZIP members"));
    }
    Ok(entries)
}

fn inflate_entry(bytes: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, Failure> {
    let compressed = &bytes[entry.data_offset..entry.data_offset + entry.compressed_size];
    let mut output = Vec::with_capacity(entry.uncompressed_size.min(MAX_LIBRARY_BYTES));
    match entry.method {
        0 => output.extend_from_slice(compressed),
        8 => {
            DeflateDecoder::new(compressed)
                .read_to_end(&mut output)
                .map_err(|error| {
                    provider_failure(format!("unable to inflate {}: {error}", entry.name))
                })?;
        }
        _ => {
            return Err(provider_failure(format!(
                "unsupported ZIP compression method for {}",
                entry.name
            )));
        }
    }
    if output.len() != entry.uncompressed_size || output.len() > MAX_LIBRARY_BYTES {
        return Err(invalid("ZIP member size does not match its declaration"));
    }
    Ok(output)
}

fn snapshot_hashes(bytes: &[u8]) -> (usize, Vec<String>, bool) {
    let magic = [0xf5, 0xf5, 0xdc, 0xdc];
    let mut sources = 0;
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    let Some(last_index) = bytes.len().checked_sub(56) else {
        return (sources, candidates, false);
    };
    let mut capped = false;
    for index in 0..=last_index {
        if bytes[index..index + 4] != magic {
            continue;
        }
        let start = index + 20;
        let end = start + 32;
        let valid = bytes[start..end]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !valid {
            continue;
        }
        sources += 1;
        let candidate = String::from_utf8_lossy(&bytes[start..end]).into_owned();
        if seen.insert(candidate.clone()) {
            if candidates.len() < MAX_HASHES {
                candidates.push(candidate);
            } else {
                capped = true;
                break;
            }
        }
    }
    (sources, candidates, capped)
}

fn elf_header_valid(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"\x7fELF"
}

fn gnu_build_ids(bytes: &[u8]) -> (Vec<String>, bool) {
    let Some((class, little_endian, program_offset, program_size, program_count)) =
        elf_program_headers(bytes)
    else {
        return (Vec::new(), false);
    };
    let mut candidates = Vec::new();
    let mut seen = Vec::new();
    let mut capped = false;
    for index in 0..program_count {
        let Some(header_offset) = index.checked_mul(program_size) else {
            break;
        };
        let Some(header) = program_offset.checked_add(header_offset) else {
            break;
        };
        let Some((kind, note_offset, note_size)) =
            elf_note_program(bytes, class, little_endian, header)
        else {
            continue;
        };
        if kind != 4 {
            continue;
        }
        scan_gnu_notes(
            bytes,
            little_endian,
            note_offset,
            note_size,
            &mut candidates,
            &mut seen,
            &mut capped,
        );
        if capped {
            break;
        }
    }
    (candidates, capped)
}

fn elf_program_headers(bytes: &[u8]) -> Option<(u8, bool, usize, usize, usize)> {
    if bytes.len() < 52 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    let class = bytes[4];
    let little_endian = match bytes[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let (program_offset, program_size, program_count) = if class == 1 {
        (
            read_uint(bytes, 28, 4, little_endian)? as usize,
            read_uint(bytes, 42, 2, little_endian)? as usize,
            read_uint(bytes, 44, 2, little_endian)? as usize,
        )
    } else if class == 2 {
        (
            read_uint(bytes, 32, 8, little_endian)? as usize,
            read_uint(bytes, 54, 2, little_endian)? as usize,
            read_uint(bytes, 56, 2, little_endian)? as usize,
        )
    } else {
        return None;
    };
    program_size
        .checked_mul(program_count)?
        .checked_add(program_offset)?;
    Some((
        class,
        little_endian,
        program_offset,
        program_size,
        program_count,
    ))
}

fn elf_note_program(
    bytes: &[u8],
    class: u8,
    little_endian: bool,
    header: usize,
) -> Option<(u64, usize, usize)> {
    let (type_offset, offset_offset, size_offset, field_size) = if class == 1 {
        (header, header + 4, header + 16, 4)
    } else {
        (header, header + 8, header + 32, 8)
    };
    let kind = read_uint(bytes, type_offset, 4, little_endian)?;
    let note_offset = read_uint(bytes, offset_offset, field_size, little_endian)? as usize;
    let note_size = read_uint(bytes, size_offset, field_size, little_endian)? as usize;
    note_offset.checked_add(note_size)?;
    Some((kind, note_offset, note_size))
}

fn scan_gnu_notes(
    bytes: &[u8],
    little_endian: bool,
    mut offset: usize,
    size: usize,
    candidates: &mut Vec<String>,
    seen: &mut Vec<String>,
    capped: &mut bool,
) {
    let Some(end) = offset.checked_add(size) else {
        return;
    };
    while offset.checked_add(12).is_some_and(|value| value <= end) {
        let Some(name_size) = read_uint(bytes, offset, 4, little_endian) else {
            return;
        };
        let Some(description_size) = read_uint(bytes, offset + 4, 4, little_endian) else {
            return;
        };
        let Some(note_type) = read_uint(bytes, offset + 8, 4, little_endian) else {
            return;
        };
        let name_start = offset + 12;
        let name_end = match name_start.checked_add(name_size as usize) {
            Some(value) => value,
            None => return,
        };
        let name_padded_end = align_four(name_end);
        let description_start = name_padded_end;
        let description_end = match description_start.checked_add(description_size as usize) {
            Some(value) => value,
            None => return,
        };
        let next = align_four(description_end);
        if next > end || description_end > bytes.len() {
            return;
        }
        if note_type == 3
            && name_end <= bytes.len()
            && bytes[name_start..name_end].starts_with(b"GNU\0")
            && (4..=64).contains(&(description_size as usize))
        {
            let candidate = hex_lower(&bytes[description_start..description_end]);
            if !seen.contains(&candidate) {
                seen.push(candidate.clone());
                if candidates.len() < MAX_HASHES {
                    candidates.push(candidate);
                } else {
                    *capped = true;
                    return;
                }
            }
        }
        offset = next;
    }
}

fn read_uint(bytes: &[u8], offset: usize, width: usize, little_endian: bool) -> Option<u64> {
    let end = offset.checked_add(width)?;
    let value = bytes.get(offset..end)?;
    let mut result = 0u64;
    for (index, byte) in value.iter().copied().enumerate() {
        let shift = if little_endian {
            index * 8
        } else {
            (width - 1 - index) * 8
        };
        result |= u64::from(byte) << shift;
    }
    Some(result)
}

fn align_four(value: usize) -> usize {
    value.saturating_add(3) & !3
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

struct LabeledStrings {
    dart_version: Option<String>,
    dart_version_capped: bool,
    toolchain: Vec<String>,
    toolchain_capped: bool,
}

fn labeled_strings(bytes: &[u8]) -> LabeledStrings {
    let mut labels = LabeledStrings {
        dart_version: None,
        dart_version_capped: false,
        toolchain: Vec::new(),
        toolchain_capped: false,
    };

    let mut line = String::new();
    let mut line_overflowed = false;

    for byte in bytes {
        if (0x20..0x7f).contains(byte) {
            if line.len() < LABEL_CARRY_BYTES {
                line.push(*byte as char);
            } else {
                line_overflowed = true;
            }
            continue;
        }

        consider_labeled_run(&mut labels, &line, line_overflowed);
        line.clear();
        line_overflowed = false;
    }

    consider_labeled_run(&mut labels, &line, line_overflowed);

    labels
}

fn consider_labeled_run(labels: &mut LabeledStrings, line: &str, overflowed: bool) {
    if line.starts_with("Dart VM version:") {
        if overflowed || line.len() > "Dart VM version:".len() + 200 {
            labels.dart_version_capped = true;
        } else if labels
            .dart_version
            .as_deref()
            .is_some_and(|value| value != line)
        {
            labels.dart_version_capped = true;
        } else {
            labels.dart_version.get_or_insert(line.to_owned());
        }
        return;
    }

    let looks_like_toolchain = line.starts_with("Android (") || line.starts_with("based on LLVM ");
    if looks_like_toolchain && (overflowed || !is_toolchain_label(line)) {
        labels.toolchain_capped = true;
        return;
    }

    let duplicate = labels.toolchain.iter().any(|value| value == line);
    if !is_toolchain_label(line) || duplicate {
        return;
    }

    if labels.toolchain.len() >= 4 {
        labels.toolchain_capped = true;
    } else {
        labels.toolchain.push(line.to_owned());
    }
}

fn is_toolchain_label(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix("based on LLVM ") {
        return rest
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
            && rest.len() <= 1 + 80;
    }
    let Some(rest) = value.strip_prefix("Android (") else {
        return false;
    };
    let Some((platform, compiler)) = rest.split_once(") clang version ") else {
        return false;
    };
    !platform.is_empty() && platform.len() <= 80 && !compiler.is_empty() && compiler.len() <= 500
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a bounded absolute APK path.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn resource_failure(reason: &str) -> Failure {
    Failure::new(
        "resource_exhausted",
        "resource",
        reason.into(),
        false,
        "Select a smaller APK or Flutter library.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn provider_failure(reason: String) -> Failure {
    Failure::new(
        "provider_error",
        "provider",
        reason,
        true,
        "Retry offline Flutter build inspection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
