//! Bounded per-file desktop byte probing.
//!
//! Faithful port of `inspectDesktopFile` and its PE/PCK helpers from
//! `src/artifacts/DesktopFileInspection.ts`. Reads only selected ranges on an
//! already admitted descriptor; it never hashes whole payloads. Range digests
//! and header facts are recorded on the file row.

use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_directory::{DirectoryError, DirectoryFile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::managed::{self, Layout};
use super::pe::{self, PeRecord};

/// Positional-read ceiling enforced by `rea-host`
/// (`MAX_DIRECTORY_POSITIONAL_READ_BYTES`). Reads above it are a format/limit
/// boundary rather than a silent truncation.
const MAX_POSITIONAL_READ_BYTES: usize = 16 * 1024 * 1024 + 32;

/// IL2CPP metadata signature (`IL2CPP_METADATA_MAGIC`).
const IL2CPP_METADATA_MAGIC: u32 = 0xfab1_1baf;

/// Probe byte and retained-metadata budget (`DesktopReadBudget`).
pub(crate) struct ReadBudget {
    pub bytes: usize,
    pub maximum: usize,
    pub retained_bytes: usize,
    pub maximum_retained_bytes: usize,
}

/// A failure raised inside file inspection, classified like the TS
/// `ArtifactReaderFailure` reasons the reader distinguishes.
#[derive(Debug)]
pub(crate) struct InspectFailure {
    /// cancelled, format, integrity, io or limit.
    pub reason: &'static str,
    pub message: String,
}

impl InspectFailure {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    fn probe_limit() -> Self {
        Self::new("limit", "Directory probe byte budget exhausted")
    }
}

type InspectResult<T> = Result<T, InspectFailure>;

fn map_directory_error(error: DirectoryError) -> InspectFailure {
    match error {
        DirectoryError::Cancelled(reason) => InspectFailure::new(
            "cancelled",
            format!("Directory inspection cancelled: {reason}"),
        ),
        DirectoryError::Changed(stage) => InspectFailure::new(
            "integrity",
            format!("Directory entry changed during {stage}"),
        ),
        DirectoryError::LimitBytes { .. } => {
            InspectFailure::new("limit", "File range exceeds the host positional-read bound")
        }
        other => InspectFailure::new("io", other.to_string()),
    }
}

fn abort_if_needed(cancellation: &Cancellation) -> InspectResult<()> {
    match cancellation.reason() {
        None => Ok(()),
        Some(_) => Err(InspectFailure::new(
            "cancelled",
            "Artifact traversal cancelled",
        )),
    }
}

/// The row facts and ranges produced by inspecting one file.
pub(crate) struct FileInspection {
    pub facts: Vec<Value>,
    pub ranges: Vec<Value>,
    /// Format/limit observations surfaced to the row's `issues`.
    pub issues: Vec<String>,
}

/// One bounded file-inspection boundary: the admitted descriptor, the shared
/// budget, cancellation, and the facts/ranges/issues accumulated on the row.
struct Prober<'a> {
    file: &'a mut DirectoryFile,
    size: usize,
    budget: &'a mut ReadBudget,
    cancellation: &'a Cancellation,
    facts: Vec<Value>,
    ranges: Vec<Value>,
    issues: Vec<String>,
}

impl Prober<'_> {
    /// `read(offset, bytes)`: bounds, budget, host-range read and digest.
    fn read(&mut self, offset: usize, bytes: usize) -> InspectResult<Vec<u8>> {
        abort_if_needed(self.cancellation)?;
        if offset > self.size || bytes > self.size - offset {
            return Err(InspectFailure::new(
                "format",
                "Declared byte range lies outside the file",
            ));
        }
        if bytes > self.budget.maximum - self.budget.bytes {
            return Err(InspectFailure::probe_limit());
        }
        if bytes > MAX_POSITIONAL_READ_BYTES {
            return Err(InspectFailure::new(
                "limit",
                "File range exceeds the host positional-read bound",
            ));
        }
        let data = self
            .file
            .read_at(offset as u64, bytes, self.cancellation)
            .map_err(map_directory_error)?;
        self.budget.bytes += data.len();
        if data.len() < bytes {
            return Err(InspectFailure::new(
                "integrity",
                "File ended before its observed extent",
            ));
        }
        abort_if_needed(self.cancellation)?;
        self.ranges.push(json!({
            "offset": offset,
            "bytes": bytes,
            "sha256": hex(&Sha256::digest(&data)),
        }));
        Ok(data)
    }

    /// `fact(observation)`: reserve the retained estimate, then record it.
    fn fact(&mut self, observation: Value) -> InspectResult<()> {
        let remaining = self.budget.maximum_retained_bytes - self.budget.retained_bytes;
        let value_budget = remaining.saturating_sub(512) / 12;
        let reservation = 512 + json_value_byte_length(&observation["value"], value_budget) * 12;
        if reservation > self.budget.maximum_retained_bytes - self.budget.retained_bytes {
            return Err(InspectFailure::new(
                "limit",
                "Directory facts reached the retained metadata budget",
            ));
        }
        self.budget.retained_bytes += reservation;
        self.facts.push(observation);
        Ok(())
    }

    /// `observe(operation)`: record format/limit failures, propagate the rest.
    fn observe(
        &mut self,
        operation: impl FnOnce(&mut Self) -> InspectResult<()>,
    ) -> InspectResult<()> {
        match operation(self) {
            Ok(()) => Ok(()),
            Err(failure) if failure.reason == "format" || failure.reason == "limit" => {
                if !self.issues.contains(&failure.message) {
                    self.issues.push(failure.message);
                }
                Ok(())
            }
            Err(failure) => Err(failure),
        }
    }
}

/// Inspect selected ranges of one admitted file (`inspectDesktopFile`).
///
/// `size` is the declared file extent (`row.bytes`). `unity_managed_directory`
/// is the owning `Data/Managed` directory when a Unity witness has not yet been
/// recorded for it; otherwise `None`.
pub(crate) fn inspect_desktop_file(
    file: &mut DirectoryFile,
    size: Option<u64>,
    budget: &mut ReadBudget,
    cancellation: &Cancellation,
    unity_managed_directory: Option<&str>,
) -> InspectResult<FileInspection> {
    let Some(size) = size else {
        return Err(InspectFailure::new(
            "limit",
            "File extent exceeds exact host offsets",
        ));
    };
    let size = usize::try_from(size)
        .map_err(|_| InspectFailure::new("limit", "File extent exceeds exact host offsets"))?;

    let mut prober = Prober {
        file,
        size,
        budget,
        cancellation,
        facts: Vec::new(),
        ranges: Vec::new(),
        issues: Vec::new(),
    };

    let prefix = prober.read(0, size.min(64))?;

    if prefix.len() >= 8 && read_u32(&prefix, 0) == IL2CPP_METADATA_MAGIC {
        prober.fact(json!({
            "kind": "il2cpp-metadata-header",
            "offset": 0,
            "value": { "magic": "0xfab11baf", "raw_version": read_u32(&prefix, 4) },
        }))?;
    }

    if prefix.len() >= 20 && &prefix[0..4] == b"GDPC" {
        prober.fact(json!({
            "kind": "godot-pck-header",
            "offset": 0,
            "value": {
                "pack_version": read_u32(&prefix, 4),
                "engine_version": [read_u32(&prefix, 8), read_u32(&prefix, 12), read_u32(&prefix, 16)],
                "placement": "standalone",
            },
        }))?;
    }

    if prefix.len() >= 16 && &prefix[0..4] == b"FORM" && &prefix[8..12] == b"GEN8" {
        let container_bytes = read_u32(&prefix, 4) as usize;
        let chunk_bytes = read_u32(&prefix, 12) as usize;
        if container_bytes >= 8
            && container_bytes <= size.saturating_sub(8)
            && chunk_bytes <= container_bytes - 8
        {
            prober.fact(json!({
                "kind": "gamemaker-form-header",
                "offset": 0,
                "value": { "container": "FORM", "first_chunk": "GEN8" },
            }))?;
        }
    }

    if prefix.len() >= 16 && &prefix[0..16] == b"-==--==--==--==-" {
        prober.fact(json!({
            "kind": "unreal-container-convention",
            "offset": 0,
            "value": { "format": "IoStore TOC" },
        }))?;
    }

    let native = prefix.len() >= 4 && (&prefix[0..4] == b"\x7fELF" || has_macho_magic(&prefix));
    if native {
        let format = if prefix[0] == 0x7f { "elf" } else { "mach-o" };
        prober.fact(json!({
            "kind": "native-image-header",
            "offset": 0,
            "value": { "format": format, "signature": hex(&prefix[0..4]) },
        }))?;
    }

    let is_mz = prefix.len() >= 2 && read_u16(&prefix, 0) == 0x5a4d;
    if prefix.len() == 64 && is_mz {
        let managed_dir = unity_managed_directory.map(str::to_owned);
        let prefix_copy = prefix.clone();
        prober.observe(|prober| inspect_pe_file(prober, &prefix_copy, managed_dir.as_deref()))?;
    }

    if (native || is_mz) && size >= 12 {
        prober.observe(inspect_pck_trailer)?;
    }

    Ok(FileInspection {
        facts: prober.facts,
        ranges: prober.ranges,
        issues: prober.issues,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// `hasMachoMagic`: the big-endian u32 at offset 0 is a Mach-O / fat magic.
fn has_macho_magic(head: &[u8]) -> bool {
    if head.len() < 4 {
        return false;
    }
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    matches!(
        magic,
        0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe | 0xcafe_babe | 0xcafe_babf
    )
}

/// `inspectPeFile`: COFF/optional-header/CLI/Unity-reference probing.
fn inspect_pe_file(
    prober: &mut Prober<'_>,
    prefix: &[u8],
    unity_managed_directory: Option<&str>,
) -> InspectResult<()> {
    let pe_offset = read_u32(prefix, 0x3c) as usize;
    let coff = prober.read(pe_offset, 24)?;
    if &coff[0..4] != b"PE\0\0" {
        return Ok(());
    }
    let optional_size = read_u16(&coff, 20) as usize;
    if optional_size > 4096 {
        return Err(InspectFailure::new(
            "format",
            "PE optional header exceeds the supported format bound",
        ));
    }
    let optional = prober.read(pe_offset + 24, optional_size)?;
    let mut record = Vec::with_capacity(coff.len() + optional.len());
    record.extend_from_slice(&coff);
    record.extend_from_slice(&optional);
    let parsed: PeRecord = match pe::parse_pe_record(&record) {
        Ok(parsed) => parsed,
        Err(message) => {
            // `row.issues.push(parsed.error); return;`
            if !prober.issues.contains(&message) {
                prober.issues.push(message);
            }
            return Ok(());
        }
    };

    prober.fact(json!({
        "kind": "native-image-header",
        "offset": pe_offset,
        "value": { "format": "pe", "machine": read_u16(&coff, 4) },
    }))?;
    if !parsed.managed {
        return Ok(());
    }

    let directories = if read_u16(&optional, 0) == 0x20b {
        112
    } else {
        96
    };
    let cli_rva = read_u32(&optional, directories + 14 * 8);
    let cli_size = read_u32(&optional, directories + 14 * 8 + 4);
    prober.fact(json!({
        "kind": "pe-cli-directory",
        "offset": pe_offset + 24 + directories + 14 * 8,
        "value": { "rva": cli_rva, "bytes": cli_size },
    }))?;

    let Some(unity_managed_directory) = unity_managed_directory else {
        return Ok(());
    };

    let section_count = read_u16(&coff, 6);
    let sections = prober.read(pe_offset + 24 + optional_size, section_count as usize * 40)?;
    let size_of_headers = read_u32(&optional, 60);

    let cli_offset =
        pe::pe_rva_to_file_offset(cli_rva, &sections, section_count, size_of_headers, 16);
    if cli_offset.is_none() || cli_size < 72 {
        return Err(InspectFailure::new(
            "format",
            "CLI metadata directory cannot be mapped",
        ));
    }
    let cli = prober.read(cli_offset.unwrap(), 16)?;
    if read_u32(&cli, 0) < 72 {
        return Err(InspectFailure::new(
            "format",
            "CLI header declares a truncated runtime header",
        ));
    }
    let metadata_bytes = read_u32(&cli, 12);
    let metadata_offset = pe::pe_rva_to_file_offset(
        read_u32(&cli, 8),
        &sections,
        section_count,
        size_of_headers,
        metadata_bytes,
    );
    let Some(metadata_offset) = metadata_offset else {
        return Err(InspectFailure::new(
            "format",
            "CLI metadata range cannot be mapped",
        ));
    };
    let bytes = prober.read(metadata_offset, metadata_bytes as usize)?;

    if let Some(fact) = decode_unity_witness(
        &bytes,
        unity_managed_directory,
        metadata_offset,
        prober.cancellation,
    )? {
        prober.fact(fact)?;
    }
    Ok(())
}

/// Decode AssemblyRef rows, recording the first UnityEngine witness.
fn decode_unity_witness(
    bytes: &[u8],
    unity_managed_directory: &str,
    metadata_offset: usize,
    cancellation: &Cancellation,
) -> InspectResult<Option<Value>> {
    let mut layout: Layout = Layout::read(bytes, 0, bytes.len()).map_err(map_managed_failure)?;
    let count = managed::assembly_reference_count(&layout);
    for index in 1..=count {
        if (index - 1) % 256 == 0 {
            abort_if_needed(cancellation)?;
        }
        let reference = managed::read_assembly_reference_name(bytes, &mut layout, index)
            .map_err(map_managed_failure)?;
        if reference.name != "UnityEngine" && !reference.name.starts_with("UnityEngine.") {
            continue;
        }
        return Ok(Some(json!({
            "kind": "unity-assembly-reference",
            "offset": metadata_offset + reference.row_offset,
            "value": {
                "name": reference.name,
                "token": reference.token,
                "managed_directory": unity_managed_directory,
            },
        })));
    }
    Ok(None)
}

fn map_managed_failure(failure: managed::ManagedFailure) -> InspectFailure {
    InspectFailure::new(
        if failure.resource_limit {
            "limit"
        } else {
            "format"
        },
        failure.message,
    )
}

/// `inspectPckTrailer`: embedded Godot pack located by a 12-byte trailer.
fn inspect_pck_trailer(prober: &mut Prober<'_>) -> InspectResult<()> {
    let size = prober.size;
    let trailer = prober.read(size - 12, 12)?;
    if &trailer[8..12] == b"GDPC" {
        let pack_size = read_u64(&trailer, 0);
        if pack_size < 20 || pack_size > (size as u64 - 12) {
            return Err(InspectFailure::new(
                "format",
                "Embedded PCK trailer declares an invalid pack extent",
            ));
        }
        let offset = size - 12 - pack_size as usize;
        let header = prober.read(offset, 20)?;
        if &header[0..4] != b"GDPC" {
            return Err(InspectFailure::new(
                "format",
                "Embedded PCK trailer does not locate a pack header",
            ));
        }
        prober.fact(json!({
            "kind": "godot-pck-header",
            "offset": offset,
            "value": {
                "pack_version": read_u32(&header, 4),
                "engine_version": [read_u32(&header, 8), read_u32(&header, 12), read_u32(&header, 16)],
                "placement": "embedded-trailer",
            },
        }))?;
    }
    Ok(())
}

/// Port of `jsonValueByteLength`; above `budget` the result only establishes
/// overflow.
fn json_value_byte_length(value: &Value, budget: usize) -> usize {
    match value {
        Value::String(text) => json_string_byte_length(text, budget),
        Value::Array(items) => {
            let mut bytes = 2 + items.len().saturating_sub(1);
            for child in items {
                if bytes > budget {
                    break;
                }
                bytes += json_value_byte_length(child, budget.saturating_sub(bytes));
            }
            bytes
        }
        Value::Object(map) => {
            let mut bytes = 2 + map.len().saturating_sub(1);
            for (key, child) in map {
                if bytes > budget {
                    break;
                }
                bytes += json_string_byte_length(key, budget.saturating_sub(bytes)) + 1;
                if bytes <= budget {
                    bytes += json_value_byte_length(child, budget.saturating_sub(bytes));
                }
            }
            bytes
        }
        Value::Null => 4,
        Value::Bool(flag) => {
            if *flag {
                4
            } else {
                5
            }
        }
        Value::Number(number) => number.to_string().len(),
    }
}

/// Port of `jsonStringByteLength` over UTF-16 code units.
fn json_string_byte_length(value: &str, budget: usize) -> usize {
    let mut bytes = 2usize;
    let units: Vec<u16> = value.encode_utf16().collect();
    let mut index = 0;
    while index < units.len() && bytes <= budget {
        let unit = units[index];
        if unit == 0x22 || unit == 0x5c {
            bytes += 2;
        } else if unit < 0x20 {
            bytes += if matches!(unit, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d) {
                2
            } else {
                6
            };
        } else if unit < 0x80 {
            bytes += 1;
        } else if unit < 0x800 {
            bytes += 2;
        } else if (0xd800..=0xdbff).contains(&unit) {
            let next = units.get(index + 1).copied().unwrap_or(0);
            if (0xdc00..=0xdfff).contains(&next) {
                bytes += 4;
                index += 1;
            } else {
                bytes += 6;
            }
        } else if (0xdc00..=0xdfff).contains(&unit) {
            bytes += 6;
        } else {
            bytes += 3;
        }
        index += 1;
    }
    bytes
}
