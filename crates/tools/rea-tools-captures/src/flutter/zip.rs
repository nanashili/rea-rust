//! In-memory ZIP reader for APK Flutter inspection.
//!
//! Compatibility owners: `src/artifacts/ZipArtifactReader.ts` (a `zip.js`
//! adapter), `src/artifacts/ArtifactReader.ts` and
//! `src/domain/artifactDecompressionBudget.ts`.
//!
//! The TypeScript reader streams members on demand through `zip.js`. This port
//! reads the already-buffered snapshot bytes and parses the central directory
//! directly. It reproduces the behaviors the Flutter family depends on: entry
//! enumeration order, logical path decoding (UTF-8 flag / Unicode Path extra
//! field / CP437), declared-size decompression budget, per-member overlap and
//! size checks, CRC validation, encryption refusal and supported compression
//! methods, with typed failure reasons. Divergences from `zip.js` that the
//! native port cannot reproduce byte-for-byte are listed in the family report.

use std::io::Read;

use crate::flutter::artifact_decompression_budget::{
    ARTIFACT_DECOMPRESSION_RATIO, MINIMUM_ARTIFACT_DECOMPRESSION_BYTES,
    artifact_decompression_budget_bytes,
};

/// `ArtifactReaderFailure.reason` for ZIP faults the adapter classifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZipFailureReason {
    Format,
    Integrity,
    Limit,
    Unavailable,
}

/// Typed ZIP reader failure equivalent to `ArtifactReaderFailure`.
#[derive(Clone, Debug)]
pub struct ZipFailure {
    pub reason: ZipFailureReason,
    pub message: String,
}

impl ZipFailure {
    fn new(reason: ZipFailureReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

// Exact `@zip.js/zip.js` error-constant texts (lib/core/zip-reader.js and
// lib/core/codecs/*). The adapter (`ZipArtifactReader.typedZipFailure`) wraps a
// format fault as `ZIP archive is malformed: <text>` and an unsupported one as
// `ZIP archive uses an unsupported feature: <text>`, so these helpers compose
// the caller-visible message exactly as the TypeScript path surfaces it.
const ERR_BAD_FORMAT: &str = "File format is not recognized";
const ERR_EOCDR_NOT_FOUND: &str = "End of central directory not found";
const ERR_EOCDR_LOCATOR_ZIP64_NOT_FOUND: &str = "End of Zip64 central directory locator not found";
const ERR_CENTRAL_DIRECTORY_NOT_FOUND: &str = "Central directory header not found";
const ERR_LOCAL_FILE_HEADER_NOT_FOUND: &str = "Local file header not found";
const ERR_EXTRAFIELD_ZIP64_NOT_FOUND: &str = "Zip64 extra field not found";
const ERR_SPLIT_ZIP_FILE: &str = "Split zip file";
const ERR_OVERLAPPING_ENTRY: &str = "Overlapping entry found";
const ERR_ENTRY_DATA_OUT_OF_BOUNDS: &str = "Entry data out of bounds";
const ERR_UNSUPPORTED_COMPRESSION: &str = "Compression method not supported";
const ERR_INVALID_UNCOMPRESSED_SIZE: &str = "Invalid uncompressed size";
const ERR_INVALID_COMPRESSED_DATA: &str = "Invalid compressed data";
const ERR_INVALID_CRC32: &str = "Invalid CRC32";

/// `typedZipFailure` for a zip.js format fault: `ZIP archive is malformed: <text>`.
fn malformed(text: &str) -> ZipFailure {
    ZipFailure::new(
        ZipFailureReason::Format,
        format!("ZIP archive is malformed: {text}"),
    )
}

/// `typedZipFailure` for a zip.js unsupported fault.
fn unsupported(text: &str) -> ZipFailure {
    ZipFailure::new(
        ZipFailureReason::Unavailable,
        format!("ZIP archive uses an unsupported feature: {text}"),
    )
}

/// One projected ZIP member, mirroring `ArtifactEntry` fields the family uses.
#[derive(Clone, Debug)]
pub struct ZipEntry {
    /// Logical path with a leading `./` prefix stripped.
    pub path: String,
    pub kind: ZipEntryKind,
    /// Uncompressed size for files, `None` for directories.
    pub declared_size: Option<u64>,
    pub encrypted: bool,
    /// Index into the central-directory enumeration (stable identity).
    index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZipEntryKind {
    File,
    Directory,
    Symlink,
}

struct CentralEntry {
    index: usize,
    method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
    directory: bool,
    projected: ZipEntry,
}

/// Lazy ZIP reader over the complete archive bytes.
pub struct ZipReader {
    bytes: Vec<u8>,
    entries: Vec<CentralEntry>,
    enumerated: bool,
}

const EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const EOCD64_LOCATOR_SIGNATURE: &[u8] = b"PK\x06\x07";
const EOCD64_SIGNATURE: &[u8] = b"PK\x06\x06";
const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";

impl ZipReader {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            entries: Vec::new(),
            enumerated: false,
        }
    }

    /// Enumerate central-directory entries once, enforcing the declared-size
    /// decompression budget in enumeration order.
    pub fn entries(&mut self) -> Result<Vec<ZipEntry>, ZipFailure> {
        if !self.enumerated {
            self.parse_central_directory()?;
            self.enumerated = true;
        }
        Ok(self
            .entries
            .iter()
            .map(|entry| entry.projected.clone())
            .collect())
    }

    fn parse_central_directory(&mut self) -> Result<(), ZipFailure> {
        let size = self.bytes.len();
        if size < 4 {
            return Err(malformed(ERR_EOCDR_NOT_FOUND));
        }
        // Find the end of central directory record (allow up to 64 KiB comment).
        let search_start = size.saturating_sub(65_557);
        let eocd = (search_start..=size - 4)
            .rev()
            .find(|&index| &self.bytes[index..index + 4] == EOCD_SIGNATURE)
            .ok_or_else(|| malformed(ERR_EOCDR_NOT_FOUND))?;

        let mut count = self.u16_at(eocd + 10)? as u64;
        let mut dir_size = self.u32_at(eocd + 12)? as u64;
        let mut dir_offset = self.u32_at(eocd + 16)? as u64;
        let disk = self.u16_at(eocd + 4)?;
        let cd_disk = self.u16_at(eocd + 6)?;
        if disk != 0 || cd_disk != 0 {
            return Err(unsupported(ERR_SPLIT_ZIP_FILE));
        }

        // Zip64 escape: any field at 0xffff/0xffffffff requires the Zip64 EOCD.
        if count == 0xffff || dir_size == 0xffff_ffff || dir_offset == 0xffff_ffff {
            let (zcount, zsize, zoffset) = self.parse_zip64(eocd)?;
            count = zcount;
            dir_size = zsize;
            dir_offset = zoffset;
        }

        if dir_offset.saturating_add(dir_size) > size as u64 {
            return Err(malformed(ERR_BAD_FORMAT));
        }

        let budget = artifact_decompression_budget_bytes(size as u64);
        let mut declared_file_bytes: u64 = 0;

        let mut cursor = dir_offset as usize;
        for index in 0..count {
            if cursor + 46 > size || self.bytes.get(cursor..cursor + 4) != Some(CENTRAL_SIGNATURE) {
                return Err(malformed(ERR_CENTRAL_DIRECTORY_NOT_FOUND));
            }
            let general_purpose = self.u16_at(cursor + 8)?;
            let method = self.u16_at(cursor + 10)?;
            let crc32 = self.u32_at(cursor + 16)?;
            let mut compressed_size = self.u32_at(cursor + 20)? as u64;
            let mut uncompressed_size = self.u32_at(cursor + 24)? as u64;
            let name_len = self.u16_at(cursor + 28)? as usize;
            let extra_len = self.u16_at(cursor + 30)? as usize;
            let comment_len = self.u16_at(cursor + 32)? as usize;
            let external_attributes = self.u32_at(cursor + 38)?;
            let mut local_header_offset = self.u32_at(cursor + 42)? as u64;

            let name_start = cursor + 46;
            let name_end = name_start + name_len;
            let extra_end = name_end + extra_len;
            let filename_raw = self
                .bytes
                .get(name_start..name_end)
                .ok_or_else(|| malformed(ERR_CENTRAL_DIRECTORY_NOT_FOUND))?
                .to_vec();
            let extra = self
                .bytes
                .get(name_end..extra_end)
                .ok_or_else(|| malformed(ERR_CENTRAL_DIRECTORY_NOT_FOUND))?
                .to_vec();

            // Zip64 extended information extra field (0x0001).
            if compressed_size == 0xffff_ffff
                || uncompressed_size == 0xffff_ffff
                || local_header_offset == 0xffff_ffff
            {
                let zip64 = find_extra_field(&extra, 0x0001)
                    .ok_or_else(|| malformed(ERR_EXTRAFIELD_ZIP64_NOT_FOUND))?;
                let mut field_cursor = 0usize;
                if uncompressed_size == 0xffff_ffff {
                    uncompressed_size =
                        read_u64_le(zip64, field_cursor).ok_or_else(zip64_truncated)?;
                    field_cursor += 8;
                }
                if compressed_size == 0xffff_ffff {
                    compressed_size =
                        read_u64_le(zip64, field_cursor).ok_or_else(zip64_truncated)?;
                    field_cursor += 8;
                }
                if local_header_offset == 0xffff_ffff {
                    local_header_offset =
                        read_u64_le(zip64, field_cursor).ok_or_else(zip64_truncated)?;
                }
            }

            let unicode_path = find_extra_field(&extra, 0x7075).and_then(|field| {
                // Info-ZIP Unicode Path: version(1) + crc32(4) + UTF-8 name.
                if field.len() >= 5 && field[0] == 1 {
                    Some(&field[5..])
                } else {
                    None
                }
            });

            let unix_mode = (external_attributes >> 16) as u16;
            let is_symlink = (unix_mode & 0o170000) == 0o120000;
            let directory = is_directory_entry(&filename_raw, external_attributes);
            let encrypted = (general_purpose & 0x0001) != 0;

            let kind = if is_symlink {
                ZipEntryKind::Symlink
            } else if directory {
                ZipEntryKind::Directory
            } else {
                ZipEntryKind::File
            };

            let logical = decode_zip_name(&filename_raw, unicode_path, general_purpose)?;
            let path = strip_dot_slash(&logical);

            // Root directory markers carry no inventory occurrence.
            let skip = matches!(kind, ZipEntryKind::Directory) && (path.is_empty() || path == ".");

            if !skip {
                if matches!(kind, ZipEntryKind::File) && !encrypted {
                    let declared = uncompressed_size;
                    if is_safe_integer(declared) {
                        declared_file_bytes = declared_file_bytes.saturating_add(declared);
                        if declared_file_bytes > budget {
                            return Err(ZipFailure::new(
                                ZipFailureReason::Limit,
                                format!(
                                    "ZIP entries declare {declared_file_bytes} uncompressed bytes, exceeding this archive's {budget}-byte decompression budget ({MINIMUM_ARTIFACT_DECOMPRESSION_BYTES}-byte minimum, {ARTIFACT_DECOMPRESSION_RATIO}x archive size); a small archive cannot expand this far"
                                ),
                            ));
                        }
                    }
                }

                let declared_size = if matches!(kind, ZipEntryKind::Directory) {
                    None
                } else {
                    Some(uncompressed_size)
                };
                let projected = ZipEntry {
                    path,
                    kind,
                    declared_size,
                    encrypted,
                    index: index as usize,
                };
                self.entries.push(CentralEntry {
                    index: index as usize,
                    method,
                    crc32,
                    compressed_size,
                    uncompressed_size,
                    local_header_offset,
                    directory,
                    projected,
                });
            }

            cursor = extra_end + comment_len;
        }
        Ok(())
    }

    fn parse_zip64(&self, eocd: usize) -> Result<(u64, u64, u64), ZipFailure> {
        if eocd < 20 || self.bytes.get(eocd - 20..eocd - 16) != Some(EOCD64_LOCATOR_SIGNATURE) {
            return Err(malformed(ERR_EOCDR_LOCATOR_ZIP64_NOT_FOUND));
        }
        let eocd64_offset = read_u64_le(&self.bytes, eocd - 20 + 8)
            .ok_or_else(|| malformed(ERR_BAD_FORMAT))? as usize;
        if eocd64_offset + 56 > self.bytes.len()
            || self.bytes.get(eocd64_offset..eocd64_offset + 4) != Some(EOCD64_SIGNATURE)
        {
            return Err(malformed(ERR_BAD_FORMAT));
        }
        let count = read_u64_le(&self.bytes, eocd64_offset + 32).unwrap_or(0);
        let dir_size = read_u64_le(&self.bytes, eocd64_offset + 40).unwrap_or(0);
        let dir_offset = read_u64_le(&self.bytes, eocd64_offset + 48).unwrap_or(0);
        Ok((count, dir_size, dir_offset))
    }

    /// Extract one member's uncompressed bytes, validating overlap, bounds,
    /// supported method, encryption and CRC exactly as the adapter requires.
    pub fn open(&self, entry: &ZipEntry) -> Result<Vec<u8>, ZipFailure> {
        let stored = self
            .entries
            .iter()
            .find(|candidate| candidate.index == entry.index)
            .ok_or_else(|| {
                ZipFailure::new(
                    ZipFailureReason::Integrity,
                    "ZIP entry metadata does not match this reader's inventory",
                )
            })?;

        if stored.projected.path != entry.path
            || stored.projected.kind != entry.kind
            || stored.projected.declared_size != entry.declared_size
            || stored.projected.encrypted != entry.encrypted
        {
            return Err(ZipFailure::new(
                ZipFailureReason::Integrity,
                "ZIP entry metadata does not match this reader's inventory",
            ));
        }

        if stored.directory || matches!(stored.projected.kind, ZipEntryKind::Symlink) {
            return Err(ZipFailure::new(
                ZipFailureReason::Format,
                "ZIP entry is not a regular file",
            ));
        }
        if stored.projected.encrypted {
            return Err(ZipFailure::new(
                ZipFailureReason::Unavailable,
                "Encrypted ZIP entry is unsupported",
            ));
        }

        let local = stored.local_header_offset as usize;
        if local + 30 > self.bytes.len()
            || self.bytes.get(local..local + 4) != Some(LOCAL_SIGNATURE)
        {
            return Err(malformed(ERR_LOCAL_FILE_HEADER_NOT_FOUND));
        }
        let local_name_len = self.u16_at(local + 26)? as usize;
        let local_extra_len = self.u16_at(local + 28)? as usize;
        let data_start = local + 30 + local_name_len + local_extra_len;
        let compressed_size = stored.compressed_size as usize;
        let data_end = data_start.saturating_add(compressed_size);
        if data_end > self.bytes.len() {
            return Err(malformed(ERR_ENTRY_DATA_OUT_OF_BOUNDS));
        }

        // Overlap verification (zip.js `checkOverlappingEntry`): a member's data
        // must not intrude on another member's local header or data.
        for other in &self.entries {
            if other.index == stored.index {
                continue;
            }
            let other_header = other.local_header_offset as usize;
            if other_header < data_end && data_start < other_header.saturating_add(30) {
                return Err(malformed(ERR_OVERLAPPING_ENTRY));
            }
        }

        let compressed = &self.bytes[data_start..data_end];
        let output = match stored.method {
            0 => {
                if compressed.len() as u64 != stored.uncompressed_size {
                    return Err(malformed(ERR_INVALID_UNCOMPRESSED_SIZE));
                }
                compressed.to_vec()
            }
            8 => {
                let mut decoder = flate2::read::DeflateDecoder::new(compressed);
                let mut output = Vec::new();
                decoder
                    .read_to_end(&mut output)
                    .map_err(|_| malformed(ERR_INVALID_COMPRESSED_DATA))?;
                if output.len() as u64 != stored.uncompressed_size {
                    return Err(malformed(ERR_INVALID_UNCOMPRESSED_SIZE));
                }
                output
            }
            _ => return Err(unsupported(ERR_UNSUPPORTED_COMPRESSION)),
        };

        // CRC-32 validation (zip.js `checkSignature`).
        if crc32(&output) != stored.crc32 {
            return Err(malformed(ERR_INVALID_CRC32));
        }

        Ok(output)
    }

    fn u16_at(&self, offset: usize) -> Result<u16, ZipFailure> {
        self.bytes
            .get(offset..offset + 2)
            .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
            .ok_or_else(|| malformed(ERR_BAD_FORMAT))
    }

    fn u32_at(&self, offset: usize) -> Result<u32, ZipFailure> {
        self.bytes
            .get(offset..offset + 4)
            .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
            .ok_or_else(|| malformed(ERR_BAD_FORMAT))
    }
}

fn zip64_truncated() -> ZipFailure {
    malformed(ERR_BAD_FORMAT)
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn is_safe_integer(value: u64) -> bool {
    value <= MAX_SAFE_INTEGER
}

fn is_directory_entry(filename_raw: &[u8], external_attributes: u32) -> bool {
    if filename_raw.last() == Some(&b'/') {
        return true;
    }
    // MS-DOS directory attribute bit (0x10) in the low external attribute byte.
    (external_attributes & 0x10) != 0
}

fn strip_dot_slash(name: &str) -> String {
    let mut rest = name;
    while let Some(stripped) = rest.strip_prefix("./") {
        rest = stripped;
    }
    rest.to_owned()
}

/// Decode a member name per the UTF-8 flag, Unicode Path extra field, or CP437.
fn decode_zip_name(
    filename_raw: &[u8],
    unicode_path: Option<&[u8]>,
    general_purpose: u16,
) -> Result<String, ZipFailure> {
    if let Some(unicode) = unicode_path {
        return decode_strict_utf8(unicode, "ZIP Unicode Path extra field is not valid UTF-8");
    }
    if (general_purpose & 0x0800) != 0 {
        return decode_strict_utf8(filename_raw, "ZIP filename is not valid UTF-8");
    }
    Ok(decode_cp437(filename_raw))
}

fn decode_strict_utf8(bytes: &[u8], message: &str) -> Result<String, ZipFailure> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ZipFailure::new(ZipFailureReason::Format, message.to_owned()))
}

/// CP437 characters for bytes 0x80-0xFF (Unicode mapping, as Python zipfile).
const CP437_HIGH_HALF: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{00A0}',
];

fn decode_cp437(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| {
            if byte < 0x80 {
                byte as char
            } else {
                CP437_HIGH_HALF[(byte - 0x80) as usize]
            }
        })
        .collect()
}

/// Walk an extra-field blob and return the payload of the requested header ID.
fn find_extra_field(extra: &[u8], header_id: u16) -> Option<&[u8]> {
    let mut cursor = 0usize;
    while cursor + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[cursor], extra[cursor + 1]]);
        let field_size = u16::from_le_bytes([extra[cursor + 2], extra[cursor + 3]]) as usize;
        let start = cursor + 4;
        let end = start + field_size;
        if end > extra.len() {
            break;
        }
        if id == header_id {
            return Some(&extra[start..end]);
        }
        cursor = end;
    }
    None
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|slice| {
        u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    })
}

/// IEEE CRC-32 (ISO-HDLC), the ZIP checksum polynomial.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
