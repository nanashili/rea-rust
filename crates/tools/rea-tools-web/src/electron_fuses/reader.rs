//! In-memory Electron fuse image reader.
//!
//! Compatibility owner: `src/electron/ElectronFuseReader.ts`
//! (`readElectronFuseImage`, `identifyContainer`, `scanSlices`, `parseWire`,
//! `identifyPe`, `electronFuseReadLimitation`, `ELECTRON_FUSE_LIMITS`). The
//! stable bytes are acquired once through `rea_host::fs::stable_file`, so the
//! sentinel search and wire parse run over resident slice bytes rather than
//! streamed chunks; the reported offsets, wires and bounds are identical.
use super::elf::elf_architecture;
use super::macho;
use super::report::{self, Format, Fuse, SENTINEL, Sentinel, Slice};

/// Sentinel-search window size, reported in the reader limitation sentence.
pub const CHUNK_BYTES: usize = 256 * 1024;
/// Per-slice sentinel ceiling.
pub const MAXIMUM_SENTINELS_PER_SLICE: usize = 32;

/// The selected container is malformed or outside the supported formats.
pub struct FuseFormatFailure {
    unsupported: bool,
    message: String,
}

impl FuseFormatFailure {
    pub fn new(unsupported: bool, message: impl Into<String>) -> Self {
        Self {
            unsupported,
            message: message.into(),
        }
    }

    pub fn malformed(message: impl Into<String>) -> Self {
        Self::new(false, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(true, message)
    }

    pub fn is_unsupported(&self) -> bool {
        self.unsupported
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A measured bound was hit before a complete fuse report could be returned.
pub struct FuseResourceFailure {
    /// `true` for the file-size boundary, `false` for the capacity boundary.
    pub file_size: bool,
    pub message: String,
}

/// A fuse read failure before a report could be produced.
pub enum ReadError {
    Format(FuseFormatFailure),
    Resource(FuseResourceFailure),
}

impl From<FuseFormatFailure> for ReadError {
    fn from(failure: FuseFormatFailure) -> Self {
        Self::Format(failure)
    }
}

/// Container identity and per-slice fuse wires. Offsets are file-absolute.
pub struct FuseImage {
    pub format: Format,
    pub slices: Vec<Slice>,
}

/// Sentence describing the file and sentinel bounds enforced by this reader.
pub fn read_limitation() -> String {
    format!(
        "The selected file is admitted as one regular file of at most 1 GiB. Sentinel search uses {CHUNK_BYTES}-byte windows, and each slice keeps at most {MAXIMUM_SENTINELS_PER_SLICE} sentinels."
    )
}

/// Decode a resident, already-admitted artifact into a fuse image.
pub fn read_image(bytes: &[u8], path: &str) -> Result<FuseImage, ReadError> {
    let (format, ranges) = identify_container(bytes, path)?;
    let mut slices = Vec::with_capacity(ranges.len());
    for range in ranges {
        let sentinels = scan_slice(bytes, &range)?;
        slices.push(Slice {
            index: range.index,
            file_offset: range.offset,
            size: range.size,
            architecture: range.architecture,
            sentinel_count: sentinels.len(),
            sentinels,
        });
    }
    Ok(FuseImage { format, slices })
}

struct SliceRange {
    index: usize,
    offset: usize,
    size: usize,
    architecture: Option<String>,
}

fn identify_container(
    bytes: &[u8],
    path: &str,
) -> Result<(Format, Vec<SliceRange>), FuseFormatFailure> {
    let size = bytes.len();
    if macho::has_macho_magic(bytes) {
        if let Some(container) = macho::identify(bytes, path)? {
            let format = if container.universal {
                Format::MachOUniversal
            } else {
                Format::MachO
            };
            let ranges = container
                .slices
                .into_iter()
                .enumerate()
                .map(|(index, slice)| SliceRange {
                    index,
                    offset: slice.offset,
                    size: slice.size,
                    architecture: slice.architecture,
                })
                .collect();
            return Ok((format, ranges));
        }
        // `readMachoImage` returned not-mach-o: fall through to the remaining
        // detectors, matching the ordered `identifyContainer` checks.
    }
    if is_elf(bytes) {
        let architecture = elf_architecture(bytes, size);
        return Ok((
            Format::Elf,
            vec![SliceRange {
                index: 0,
                offset: 0,
                size,
                architecture,
            }],
        ));
    }
    if let Some(architecture) = identify_pe(bytes, size) {
        return Ok((
            Format::Pe,
            vec![SliceRange {
                index: 0,
                offset: 0,
                size,
                architecture,
            }],
        ));
    }
    Err(FuseFormatFailure::unsupported(format!(
        "Selected artifact {path} does not contain a Mach-O, ELF, or PE container."
    )))
}

fn is_elf(head: &[u8]) -> bool {
    head.len() >= 4 && head[0] == 0x7f && head[1] == 0x45 && head[2] == 0x4c && head[3] == 0x46
}

/// Port of `identifyPe`: an MZ/PE signature, with COFF machine architecture
/// only when no managed OS override is present.
fn identify_pe(bytes: &[u8], size: usize) -> Option<Option<String>> {
    if size < 64 {
        return None;
    }
    if bytes[0] != 0x4d || bytes[1] != 0x5a {
        return None;
    }
    let offset = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    if offset < 64 || offset > super::pe::MAXIMUM_PE_HEADER_OFFSET || offset > size - 4 {
        return None;
    }
    let header = bytes.get(offset..offset + 24.min(size - offset))?;
    if header.len() < 4 {
        return None;
    }
    if u32::from_le_bytes([header[0], header[1], header[2], header[3]]) != 0x0000_4550 {
        return None;
    }
    // A signature establishes the scan boundary; only a complete COFF header
    // establishes its machine. Managed OS overrides need separate proof.
    let architecture = if header.len() == 24 {
        let machine = u16::from_le_bytes([header[4], header[5]]);
        super::pe::decode_machine(machine)
            .filter(|decoded| !decoded.native_os_override)
            .map(|decoded| decoded.architecture.to_owned())
    } else {
        None
    };
    Some(architecture)
}

fn scan_slice(bytes: &[u8], range: &SliceRange) -> Result<Vec<Sentinel>, ReadError> {
    let slice_start = range.offset;
    let slice_end = range.offset + range.size;
    let slice = &bytes[slice_start..slice_end];
    let mut hits: Vec<usize> = Vec::new();
    let mut from = 0usize;
    while from + SENTINEL.len() <= slice.len() {
        let Some(found) = find_bytes(&slice[from..], SENTINEL) else {
            break;
        };
        let sentinel_offset = slice_start + from + found;
        if !hits.contains(&sentinel_offset) {
            if hits.len() >= MAXIMUM_SENTINELS_PER_SLICE {
                return Err(ReadError::Resource(FuseResourceFailure {
                    file_size: false,
                    message: format!(
                        "Slice {} contains more than {MAXIMUM_SENTINELS_PER_SLICE} Electron fuse sentinels.",
                        range.index
                    ),
                }));
            }
            hits.push(sentinel_offset);
        }
        from = from + found + 1;
    }
    let mut sentinels = Vec::with_capacity(hits.len());
    for offset in hits {
        sentinels.push(parse_wire(bytes, offset, slice_end));
    }
    Ok(sentinels)
}

/// Port of `parseWire`: decode the wire header and fuse bytes within slice bounds.
fn parse_wire(bytes: &[u8], sentinel_offset: usize, slice_end: usize) -> Sentinel {
    let wire_start = sentinel_offset + SENTINEL.len();
    let available = slice_end.saturating_sub(wire_start);
    if available < 1 {
        return Sentinel {
            sentinel_offset,
            wire_version: None,
            declared_length: None,
            fuses: Vec::new(),
            complete: false,
        };
    }
    let header_len = available.min(2);
    let header = &bytes[wire_start..wire_start + header_len];
    let wire_version = header.first().copied();
    if wire_version.is_none() || header.len() < 2 {
        return Sentinel {
            sentinel_offset,
            wire_version,
            declared_length: None,
            fuses: Vec::new(),
            complete: false,
        };
    }
    let declared = header[1];
    let fuse_length = (declared as usize).min(available - 2);
    let fuse_bytes = if fuse_length == 0 {
        &[][..]
    } else {
        &bytes[wire_start + 2..wire_start + 2 + fuse_length]
    };
    let version = wire_version.unwrap_or_default();
    let fuses = fuse_bytes
        .iter()
        .enumerate()
        .map(|(index, &raw)| Fuse {
            index,
            name: report::fuse_name(version, index),
            state: report::fuse_state(raw),
            raw_byte: raw,
        })
        .collect();
    Sentinel {
        sentinel_offset,
        wire_version,
        declared_length: Some(declared),
        fuses,
        complete: fuse_bytes.len() == declared as usize,
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
