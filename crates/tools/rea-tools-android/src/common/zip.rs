//! Bounded ZIP central-directory enumeration.
//!
//! Only metadata is read: the end-of-central-directory record (including the
//! ZIP64 locator) and the central directory itself, bounded by the caller's
//! metadata budget. Entry bodies are never decompressed.
use rea_core::cancellation::Cancellation;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const EOCD_BYTES: u64 = 22;
const MAX_COMMENT_BYTES: u64 = 65_535;

/// One central-directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZipEntry {
    pub path: String,
    pub directory: bool,
    pub encrypted: bool,
}

/// Why the archive metadata could not be enumerated.
#[derive(Debug)]
pub enum ZipError {
    Cancelled(String),
    Malformed(String),
    Limit { maximum_bytes: usize },
    Io(std::io::Error),
}

impl fmt::Display for ZipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled(_) => formatter.write_str("Archive read cancelled"),
            Self::Malformed(reason) => formatter.write_str(reason),
            Self::Limit { maximum_bytes } => write!(
                formatter,
                "ZIP central directory exceeds the {maximum_bytes}-byte metadata budget"
            ),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

fn read_exact_at(file: &mut File, offset: u64, length: usize) -> Result<Vec<u8>, ZipError> {
    file.seek(SeekFrom::Start(offset)).map_err(ZipError::Io)?;
    let mut buffer = vec![0u8; length];
    let mut total = 0;
    while total < length {
        let read = file.read(&mut buffer[total..]).map_err(ZipError::Io)?;
        if read == 0 {
            return Err(ZipError::Malformed(
                "ZIP metadata extends beyond the end of the file".into(),
            ));
        }
        total += read;
    }
    Ok(buffer)
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn checkpoint(cancellation: &Cancellation) -> Result<(), ZipError> {
    match cancellation.reason() {
        Some(reason) => Err(ZipError::Cancelled(reason.to_owned())),
        None => Ok(()),
    }
}

/// Enumerate every central-directory entry of the archive in `file`.
pub fn central_directory_entries(
    file: &mut File,
    size: u64,
    maximum_metadata_bytes: usize,
    cancellation: &Cancellation,
) -> Result<Vec<ZipEntry>, ZipError> {
    checkpoint(cancellation)?;
    if size < EOCD_BYTES {
        return Err(ZipError::Malformed(
            "File is too small to contain a ZIP end-of-central-directory record".into(),
        ));
    }
    let tail_length = (EOCD_BYTES + MAX_COMMENT_BYTES).min(size);
    let tail_start = size - tail_length;
    let tail = read_exact_at(file, tail_start, tail_length as usize)?;
    let mut eocd = None;
    for offset in (0..=tail.len() - EOCD_BYTES as usize).rev() {
        if u32_at(&tail, offset) == EOCD_SIGNATURE {
            let comment = u16_at(&tail, offset + 20) as usize;
            if offset + EOCD_BYTES as usize + comment == tail.len() {
                eocd = Some(offset);
                break;
            }
        }
    }
    let Some(eocd) = eocd else {
        return Err(ZipError::Malformed(
            "ZIP end-of-central-directory record was not found".into(),
        ));
    };
    let mut entries = u64::from(u16_at(&tail, eocd + 10));
    let mut directory_size = u64::from(u32_at(&tail, eocd + 12));
    let mut directory_offset = u64::from(u32_at(&tail, eocd + 16));
    if entries == 0xffff || directory_size == 0xffff_ffff || directory_offset == 0xffff_ffff {
        let locator_offset = (tail_start + eocd as u64)
            .checked_sub(20)
            .ok_or_else(|| ZipError::Malformed("ZIP64 locator is missing".into()))?;
        let locator = read_exact_at(file, locator_offset, 20)?;
        if u32_at(&locator, 0) != ZIP64_LOCATOR_SIGNATURE {
            return Err(ZipError::Malformed("ZIP64 locator is missing".into()));
        }
        let record_offset = u64_at(&locator, 8);
        let record = read_exact_at(file, record_offset, 56)?;
        if u32_at(&record, 0) != ZIP64_EOCD_SIGNATURE {
            return Err(ZipError::Malformed(
                "ZIP64 end-of-central-directory record is invalid".into(),
            ));
        }
        entries = u64_at(&record, 32);
        directory_size = u64_at(&record, 40);
        directory_offset = u64_at(&record, 48);
    }
    if directory_size > maximum_metadata_bytes as u64 {
        return Err(ZipError::Limit {
            maximum_bytes: maximum_metadata_bytes,
        });
    }
    if directory_offset
        .checked_add(directory_size)
        .is_none_or(|end| end > size)
    {
        return Err(ZipError::Malformed(
            "ZIP central directory extends beyond the end of the file".into(),
        ));
    }
    checkpoint(cancellation)?;
    let directory = read_exact_at(file, directory_offset, directory_size as usize)?;
    let mut result = Vec::new();
    let mut offset = 0usize;
    for _ in 0..entries {
        checkpoint(cancellation)?;
        if offset + 46 > directory.len() || u32_at(&directory, offset) != CENTRAL_SIGNATURE {
            return Err(ZipError::Malformed(
                "ZIP central directory entry is truncated or invalid".into(),
            ));
        }
        let flags = u16_at(&directory, offset + 8);
        let name_length = u16_at(&directory, offset + 28) as usize;
        let extra_length = u16_at(&directory, offset + 30) as usize;
        let comment_length = u16_at(&directory, offset + 32) as usize;
        let name_start = offset + 46;
        let next = name_start + name_length + extra_length + comment_length;
        if next > directory.len() {
            return Err(ZipError::Malformed(
                "ZIP central directory entry is truncated or invalid".into(),
            ));
        }
        let name =
            String::from_utf8_lossy(&directory[name_start..name_start + name_length]).into_owned();
        result.push(ZipEntry {
            directory: name.ends_with('/'),
            encrypted: flags & 1 == 1,
            path: name,
        });
        offset = next;
    }
    Ok(result)
}
