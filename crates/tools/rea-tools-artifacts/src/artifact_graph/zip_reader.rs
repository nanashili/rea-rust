//! Self-contained ZIP-package reader over an in-memory archive capture.
//!
//! Compatibility owner: `src/artifacts/ZipArtifactReader.ts` (the `@zip.js`
//! adapter). Ports the central-directory enumeration, Zip64 extents, CP437 /
//! UTF-8 name decoding, symlink and executable marking, the per-archive
//! decompression budget and CRC32-verified stored/deflate member reads. zip.js
//! archive faults map to typed `format`/`unavailable` reader failures.
use super::reader::{ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure};
use flate2::read::DeflateDecoder;
use rea_core::cancellation::Cancellation;
use std::io::Read;

const ARTIFACT_DECOMPRESSION_RATIO: u64 = 500;
const MINIMUM_ARTIFACT_DECOMPRESSION_BYTES: u64 = 256 * 1024 * 1024;

fn decompression_budget(compressed_bytes: u64) -> u64 {
    MINIMUM_ARTIFACT_DECOMPRESSION_BYTES.max(compressed_bytes * ARTIFACT_DECOMPRESSION_RATIO)
}

/// One parsed central-directory record.
#[derive(Clone)]
struct ZipEntry {
    index: usize,
    path: String,
    source_path: String,
    kind: &'static str,
    uncompressed_size: u64,
    compressed_size: u64,
    local_header_offset: u64,
    compression_method: u16,
    crc32: u32,
    encrypted: bool,
    executable: bool,
    directory: bool,
    is_symlink: bool,
}

pub struct ZipArtifactReader {
    format: &'static str,
    bytes: Vec<u8>,
    entries: Vec<ZipEntry>,
    parsed: bool,
}

impl ZipArtifactReader {
    pub fn new(format: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            format,
            bytes,
            entries: Vec::new(),
            parsed: false,
        }
    }

    fn parse(&mut self) -> Result<(), ReaderFailure> {
        if self.parsed {
            return Ok(());
        }
        let (cd_offset, cd_size, total) = self.locate_central_directory()?;
        let data = &self.bytes;
        let cd_start = cd_offset as usize;
        let cd_end = (cd_offset + cd_size) as usize;
        if cd_end > data.len() || cd_start > cd_end {
            return Err(malformed("central directory is outside the archive"));
        }
        let mut cursor = cd_start;
        let mut entries = Vec::new();
        for index in 0..total {
            if cursor + 46 > cd_end {
                return Err(malformed("central directory record is truncated"));
            }
            if &data[cursor..cursor + 4] != [0x50, 0x4b, 0x01, 0x02] {
                return Err(malformed("central directory record has a bad signature"));
            }
            let gp_flags = u16(data, cursor + 8);
            let method = u16(data, cursor + 10);
            let crc32 = u32(data, cursor + 16);
            let mut compressed = u32(data, cursor + 20) as u64;
            let mut uncompressed = u32(data, cursor + 24) as u64;
            let name_len = u16(data, cursor + 28) as usize;
            let extra_len = u16(data, cursor + 30) as usize;
            let comment_len = u16(data, cursor + 32) as usize;
            let external_attrs = u32(data, cursor + 38);
            let mut local_offset = u32(data, cursor + 42) as u64;
            let name_start = cursor + 46;
            let name_end = name_start + name_len;
            let extra_end = name_end + extra_len;
            let record_end = extra_end + comment_len;
            if record_end > cd_end {
                return Err(malformed("central directory record overruns the directory"));
            }
            let name_bytes = &data[name_start..name_end];
            let utf8_flag = (gp_flags & 0x0800) != 0;
            let encrypted = (gp_flags & 0x0001) != 0;
            let extra = &data[name_end..extra_end];
            // Zip64 extended information: patch 0xffffffff placeholders.
            let mut unicode_name: Option<String> = None;
            parse_extra_fields(
                extra,
                &mut uncompressed,
                &mut compressed,
                &mut local_offset,
                name_bytes,
                &mut unicode_name,
            )?;
            let source_path = match unicode_name {
                Some(name) => name,
                None if utf8_flag => decode_utf8(name_bytes)?,
                None => decode_cp437(name_bytes),
            };
            let path = strip_dot_prefix(&source_path);
            let unix_mode = (external_attrs >> 16) as u32;
            let is_symlink = (unix_mode & 0o170000) == 0o120000;
            let directory = source_path.ends_with('/');
            let kind = if is_symlink {
                "symlink"
            } else if directory {
                "directory"
            } else {
                "file"
            };
            let executable = kind == "file" && (unix_mode & 0o111) != 0;
            entries.push(ZipEntry {
                index,
                path,
                source_path,
                kind,
                uncompressed_size: uncompressed,
                compressed_size: compressed,
                local_header_offset: local_offset,
                compression_method: method,
                crc32,
                encrypted,
                executable,
                directory,
                is_symlink,
            });
            cursor = record_end;
        }
        self.entries = entries;
        self.parsed = true;
        Ok(())
    }

    /// Find the End Of Central Directory record (and the Zip64 EOCD when a
    /// locator is present) and return `(cd_offset, cd_size, total_records)`.
    fn locate_central_directory(&self) -> Result<(u64, u64, usize), ReaderFailure> {
        let data = &self.bytes;
        if data.len() < 22 {
            return Err(malformed("archive is too small for an EOCD record"));
        }
        // Search backwards for the EOCD signature within the max comment window.
        let max_back = 22 + 0xffff;
        let start = data.len().saturating_sub(max_back);
        let mut eocd: Option<usize> = None;
        let mut index = data.len() - 22;
        loop {
            if &data[index..index + 4] == [0x50, 0x4b, 0x05, 0x06] {
                eocd = Some(index);
                break;
            }
            if index == start {
                break;
            }
            index -= 1;
        }
        let eocd = eocd.ok_or_else(|| malformed("end of central directory not found"))?;
        let disk = u16(data, eocd + 4);
        if disk != 0 {
            return Err(unavailable("split ZIP file is unsupported"));
        }
        let mut total = u16(data, eocd + 10) as usize;
        let mut cd_size = u32(data, eocd + 12) as u64;
        let mut cd_offset = u32(data, eocd + 16) as u64;
        // Zip64 EOCD locator sits immediately before the EOCD (20 bytes).
        if eocd >= 20 && &data[eocd - 20..eocd - 16] == [0x50, 0x4b, 0x06, 0x07] {
            let z64_offset = u64le(data, eocd - 20 + 8) as usize;
            if z64_offset + 56 <= data.len()
                && &data[z64_offset..z64_offset + 4] == [0x50, 0x4b, 0x06, 0x06]
            {
                total = u64le(data, z64_offset + 32) as usize;
                cd_size = u64le(data, z64_offset + 40);
                cd_offset = u64le(data, z64_offset + 48);
            } else {
                return Err(malformed("Zip64 end of central directory not found"));
            }
        }
        Ok((cd_offset, cd_size, total))
    }

    fn member_bytes(&self, entry: &ZipEntry) -> Result<Vec<u8>, ReaderFailure> {
        let data = &self.bytes;
        let lho = entry.local_header_offset as usize;
        if lho + 30 > data.len() || &data[lho..lho + 4] != [0x50, 0x4b, 0x03, 0x04] {
            return Err(malformed("local file header not found"));
        }
        let name_len = u16(data, lho + 26) as usize;
        let extra_len = u16(data, lho + 28) as usize;
        let data_start = lho + 30 + name_len + extra_len;
        let compressed = entry.compressed_size as usize;
        if data_start + compressed > data.len() {
            return Err(malformed("entry data extends beyond the archive"));
        }
        let compressed_bytes = &data[data_start..data_start + compressed];
        let output = match entry.compression_method {
            0 => compressed_bytes.to_vec(),
            8 => {
                let mut decoder = DeflateDecoder::new(compressed_bytes);
                let mut out = Vec::with_capacity(entry.uncompressed_size as usize);
                decoder
                    .read_to_end(&mut out)
                    .map_err(|_| malformed("invalid compressed data"))?;
                out
            }
            _ => return Err(unavailable("unsupported compression method")),
        };
        if output.len() as u64 != entry.uncompressed_size {
            return Err(malformed("invalid uncompressed size"));
        }
        if crc32(&output) != entry.crc32 {
            return Err(malformed("invalid CRC-32"));
        }
        Ok(output)
    }
}

impl ArtifactReader for ZipArtifactReader {
    fn format(&self) -> &'static str {
        self.format
    }

    fn entries(
        &mut self,
        cancellation: &Cancellation,
        _omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        self.parse()?;
        let budget = decompression_budget(self.bytes.len() as u64);
        let mut declared: u64 = 0;
        let mut out = Vec::new();
        let entries = self.entries.clone();
        for entry in &entries {
            if cancellation.reason().is_some() {
                return Err(ReaderFailure::new("cancelled", "ZIP operation cancelled"));
            }
            // Root directory markers carry no inventory occurrence.
            if entry.kind == "directory" && (entry.path.is_empty() || entry.path == ".") {
                continue;
            }
            if entry.kind == "file" && !entry.encrypted {
                declared += entry.uncompressed_size;
                if declared > budget {
                    return Err(ReaderFailure::new(
                        "limit",
                        format!(
                            "ZIP entries declare {declared} uncompressed bytes, exceeding this archive's {budget}-byte decompression budget ({MINIMUM_ARTIFACT_DECOMPRESSION_BYTES}-byte minimum, {ARTIFACT_DECOMPRESSION_RATIO}x archive size); a small archive cannot expand this far"
                        ),
                    ));
                }
            }
            let mut limitations = Vec::new();
            if entry.is_symlink {
                limitations.push("Archive symlink target was not read.".to_owned());
            }
            if entry.path != entry.source_path {
                limitations.push(format!(
                    "ZIP member name {:?} has a leading current-directory prefix omitted from its logical path.",
                    entry.source_path
                ));
            }
            out.push(ArtifactEntry {
                path: entry.path.clone(),
                kind: entry.kind,
                declared_size: if entry.directory || entry.is_symlink {
                    None
                } else {
                    Some(entry.uncompressed_size)
                },
                compressed_size: if entry.directory || entry.is_symlink {
                    None
                } else {
                    Some(entry.compressed_size)
                },
                executable: entry.executable,
                encrypted: entry.encrypted,
                byte_offset: None,
                declared_sha256: None,
                unpacked: false,
                limitations,
                adapter_key: format!("zip-entry:{}", entry.index),
            });
        }
        Ok(out)
    }

    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        self.parse()?;
        if cancellation.reason().is_some() {
            return Err(ReaderFailure::new("cancelled", "ZIP operation cancelled"));
        }
        let index: usize = entry
            .adapter_key
            .strip_prefix("zip-entry:")
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| {
                ReaderFailure::new(
                    "integrity",
                    "ZIP entry metadata does not match this reader's inventory",
                )
            })?;
        let zip_entry = self
            .entries
            .iter()
            .find(|candidate| candidate.index == index)
            .cloned()
            .ok_or_else(|| {
                ReaderFailure::new(
                    "integrity",
                    "ZIP entry metadata does not match this reader's inventory",
                )
            })?;
        if zip_entry.directory || zip_entry.is_symlink {
            return Err(ReaderFailure::new(
                "format",
                "ZIP entry is not a regular file",
            ));
        }
        if zip_entry.encrypted {
            return Err(ReaderFailure::new(
                "unavailable",
                "Encrypted ZIP entry is unsupported",
            ));
        }
        self.member_bytes(&zip_entry)
    }

    fn close(&mut self) -> Result<(), ReaderFailure> {
        self.bytes = Vec::new();
        self.entries = Vec::new();
        Ok(())
    }
}

fn malformed(detail: &str) -> ReaderFailure {
    ReaderFailure::new("format", format!("ZIP archive is malformed: {detail}"))
}

fn unavailable(detail: &str) -> ReaderFailure {
    ReaderFailure::new(
        "unavailable",
        format!("ZIP archive uses an unsupported feature: {detail}"),
    )
}

fn strip_dot_prefix(path: &str) -> String {
    let mut rest = path;
    while let Some(stripped) = rest.strip_prefix("./") {
        rest = stripped;
    }
    rest.to_owned()
}

fn parse_extra_fields(
    extra: &[u8],
    uncompressed: &mut u64,
    compressed: &mut u64,
    local_offset: &mut u64,
    name_bytes: &[u8],
    unicode_name: &mut Option<String>,
) -> Result<(), ReaderFailure> {
    let mut cursor = 0usize;
    while cursor + 4 <= extra.len() {
        let header_id = u16(extra, cursor);
        let size = u16(extra, cursor + 2) as usize;
        let body_start = cursor + 4;
        if body_start + size > extra.len() {
            break;
        }
        let body = &extra[body_start..body_start + size];
        if header_id == 0x0001 {
            // Zip64 extended information: fields appear only for 0xffffffff.
            let mut offset = 0usize;
            if *uncompressed == 0xffff_ffff && offset + 8 <= body.len() {
                *uncompressed = u64le(body, offset);
                offset += 8;
            }
            if *compressed == 0xffff_ffff && offset + 8 <= body.len() {
                *compressed = u64le(body, offset);
                offset += 8;
            }
            if *local_offset == 0xffff_ffff && offset + 8 <= body.len() {
                *local_offset = u64le(body, offset);
            }
        } else if header_id == 0x7075 {
            // Info-ZIP Unicode Path extra field: version(1) crc(4) utf-8 name.
            if body.len() > 5 {
                *unicode_name = Some(decode_utf8(&body[5..])?);
                let _ = name_bytes;
            }
        }
        cursor = body_start + size;
    }
    Ok(())
}

fn decode_utf8(bytes: &[u8]) -> Result<String, ReaderFailure> {
    std::str::from_utf8(bytes)
        .map(|value| value.trim_start_matches('\u{feff}').to_owned())
        .map_err(|_| ReaderFailure::new("format", "ZIP filename is not valid UTF-8"))
}

const CP437_HIGH_HALF: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{00a0}',
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

fn u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn u64le(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
