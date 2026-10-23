//! String inventory and byte reads from the admitted object file.
//!
//! Both read file-backed section contents of the verified target bytes with
//! the `object` parser; zero-fill sections have no file bytes and are not
//! read. Loader fixups and relocations are not applied.
use std::ops::Range;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, SectionKind};

/// Fewest characters in a reported string (the engine's own minimum).
pub(crate) const MIN_STRING_CHARACTERS: usize = 4;
/// Longest reported string, in UTF-8 bytes.
pub(crate) const MAX_STRING_BYTES: usize = 64 * 1024;
/// Largest single byte read.
pub(crate) const MAX_READ_BYTES: usize = 1024 * 1024;

/// One NUL-terminated string at `address`; `byte_length` includes the NUL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ImageString {
    pub address: u64,
    pub value: String,
    pub byte_length: usize,
}

fn string_section(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::ReadOnlyString
            | SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyDataWithRel
            | SectionKind::Data
            | SectionKind::OtherString
    )
}

fn printable(text: &str) -> bool {
    text.chars()
        .all(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'))
}

/// Every NUL-terminated printable UTF-8 run of at least four characters in
/// file-backed data and string sections, in address order. A run starts at
/// the section start or after a NUL; runs longer than 64 KiB are skipped.
pub(crate) fn strings(bytes: &[u8]) -> Result<Vec<ImageString>> {
    let file = object::File::parse(bytes).context("Parse the admitted target for strings")?;
    let mut strings = Vec::new();
    for section in file.sections() {
        if !string_section(section.kind()) {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        let base = section.address();
        let mut start = 0_usize;
        while start < data.len() {
            let Some(length) = data[start..].iter().position(|byte| *byte == 0) else {
                break;
            };
            let run = &data[start..start + length];
            if length > 0
                && length <= MAX_STRING_BYTES
                && let Ok(text) = std::str::from_utf8(run)
                && text.chars().count() >= MIN_STRING_CHARACTERS
                && printable(text)
            {
                strings.push(ImageString {
                    address: base + start as u64,
                    value: text.to_owned(),
                    byte_length: length + 1,
                });
            }
            start += length + 1;
        }
    }
    strings.sort_by_key(|string| string.address);
    strings.dedup_by_key(|string| string.address);
    Ok(strings)
}

/// File-backed section ranges: `(address range, file offset of the start)`.
pub(crate) fn file_ranges(bytes: &[u8]) -> Result<Vec<(Range<u64>, usize)>> {
    let file = object::File::parse(bytes).context("Parse the admitted target for byte reads")?;
    let mut ranges = Vec::new();
    for section in file.sections() {
        let Some((offset, size)) = section.file_range() else {
            continue;
        };
        if size == 0 || section.kind() == SectionKind::UninitializedData {
            continue;
        }
        let start = section.address();
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        let Ok(offset) = usize::try_from(offset) else {
            continue;
        };
        ranges.push((start..end, offset));
    }
    ranges.sort_by_key(|(range, _)| range.start);
    Ok(ranges)
}

/// Read up to `length` bytes from `address`, stopping at the first byte
/// without file-backed section contents.
pub(crate) fn read(bytes: &[u8], ranges: &[(Range<u64>, usize)], address: u64, length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length.min(MAX_READ_BYTES));
    let mut current = address;
    while output.len() < length {
        let index = ranges.partition_point(|(range, _)| range.start <= current);
        let Some((range, offset)) = index.checked_sub(1).and_then(|index| ranges.get(index)) else {
            break;
        };
        if !range.contains(&current) {
            break;
        }
        let within = (current - range.start) as usize;
        let available = (range.end - current) as usize;
        let take = available.min(length - output.len());
        let Some(slice) = bytes.get(offset + within..offset + within + take) else {
            break;
        };
        output.extend_from_slice(slice);
        current += take as u64;
    }
    output
}
