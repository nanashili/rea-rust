//! String inventory and byte reads from the admitted object file.
//!
//! Both read file-backed section contents of the verified target bytes with
//! the `object` parser; zero-fill sections have no file bytes and are not
//! read. Loader fixups and relocations are not applied.
use std::ops::Range;

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSection, ObjectSegment, SectionKind};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoverageRange {
    pub address: Range<u64>,
    pub name: String,
    pub file_offset: Option<usize>,
    pub initialized: bool,
    pub loaded: bool,
}

fn validated_file_offset(
    bytes_len: usize,
    selected_offset: u64,
    section_offset: u64,
    file_size: u64,
) -> Result<usize> {
    let absolute_offset = section_offset
        .checked_add(selected_offset)
        .context("Object section file offset overflows")?;
    let relative_offset = usize::try_from(
        absolute_offset
            .checked_sub(selected_offset)
            .context("Object section precedes the selected image slice")?,
    )
    .context("Object section file offset exceeds host indexing")?;
    let file_size =
        usize::try_from(file_size).context("Object section file extent exceeds host indexing")?;
    ensure!(
        relative_offset
            .checked_add(file_size)
            .is_some_and(|end| end <= bytes_len),
        "Object section file extent exceeds the selected image bytes"
    );
    usize::try_from(absolute_offset).context("Object section file offset exceeds host indexing")
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
pub(crate) fn file_ranges(bytes: &[u8], file_offset: u64) -> Result<Vec<(Range<u64>, usize)>> {
    Ok(coverage_ranges(bytes, file_offset)?
        .into_iter()
        .filter_map(|range| range.file_offset.map(|offset| (range.address, offset)))
        .collect())
}

pub(crate) fn coverage_ranges(bytes: &[u8], file_offset: u64) -> Result<Vec<CoverageRange>> {
    let file = object::File::parse(bytes).context("Parse the admitted target for coverage")?;
    let load_ranges = mapped_ranges_from_file(&file)?;
    let mut ranges = Vec::new();
    for section in file.sections() {
        let memory_size = section.size();
        if memory_size == 0 {
            continue;
        }
        let start = section.address();
        let end = start
            .checked_add(memory_size)
            .context("Object section address range overflows")?;
        let name = section
            .name()
            .context("Read object section name")?
            .to_owned();
        let loaded = load_ranges
            .iter()
            .any(|load| load.start <= start && end <= load.end);
        let file_range = section.file_range();
        let file_size = file_range.map(|(_, size)| size).unwrap_or(0);
        if let Some((section_offset, file_size)) = file_range {
            validated_file_offset(bytes.len(), file_offset, section_offset, file_size)?;
        }
        let initialized_size = if section.kind() == SectionKind::UninitializedData {
            0
        } else {
            file_size.min(memory_size)
        };

        let initialized_offset = if initialized_size == 0 {
            None
        } else {
            let (section_offset, _) =
                file_range.context("Initialized object section has no file range")?;
            Some(validated_file_offset(
                bytes.len(),
                file_offset,
                section_offset,
                initialized_size,
            )?)
        };

        if initialized_size > 0 {
            let initialized_end = start
                .checked_add(initialized_size)
                .context("Initialized object section range overflows")?;
            ranges.push(CoverageRange {
                address: start..initialized_end,
                name: name.clone(),
                file_offset: initialized_offset,
                initialized: true,
                loaded,
            });
        }
        if initialized_size < memory_size {
            let tail_start = start
                .checked_add(initialized_size)
                .context("Object section zero-fill range overflows")?;
            ranges.push(CoverageRange {
                address: tail_start..end,
                name,
                file_offset: None,
                initialized: false,
                loaded,
            });
        }
    }
    ranges.sort_by_key(|range| range.address.start);
    Ok(ranges)
}

/// Return validated virtual ranges backed by loadable object segments.
///
/// These ranges are the authority for whether an address belongs to the
/// mapped image. Section ranges describe object contents, but do not include
/// segment padding and can include sections that are not loaded at runtime.
pub(crate) fn mapped_ranges(bytes: &[u8]) -> Result<Vec<Range<u64>>> {
    let file = object::File::parse(bytes).context("Parse the admitted target mappings")?;
    mapped_ranges_from_file(&file)
}

fn mapped_ranges_from_file(file: &object::File<'_>) -> Result<Vec<Range<u64>>> {
    file.segments()
        .map(|segment| {
            let end = segment
                .address()
                .checked_add(segment.size())
                .context("Object load segment address range overflows")?;
            Ok(segment.address()..end)
        })
        .collect()
}

/// Read up to `length` bytes from `address`, stopping at the first byte
/// without file-backed section contents.
pub(crate) fn read(
    bytes: &[u8],
    ranges: &[(Range<u64>, usize)],
    slice_offset: u64,
    address: u64,
    length: usize,
) -> Vec<u8> {
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
        let Ok(within) = usize::try_from(current - range.start) else {
            break;
        };
        let Ok(available) = usize::try_from(range.end - current) else {
            break;
        };
        let take = available.min(length - output.len());
        let Some(relative_offset) = (*offset as u64)
            .checked_sub(slice_offset)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            break;
        };
        let Some(start) = relative_offset.checked_add(within) else {
            break;
        };
        let Some(end) = start.checked_add(take) else {
            break;
        };
        let Some(slice) = bytes.get(start..end) else {
            break;
        };
        output.extend_from_slice(slice);
        let Some(next) = current.checked_add(take as u64) else {
            break;
        };
        current = next;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{coverage_ranges, mapped_ranges, read, validated_file_offset};

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn pe_with_virtual_tail(raw_offset: u32, raw_size: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[0..2].copy_from_slice(b"MZ");
        put_u32(&mut bytes, 60, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut bytes, 0x84, 0x14c);
        put_u16(&mut bytes, 0x86, 1);
        put_u16(&mut bytes, 0x94, 96);
        put_u16(&mut bytes, 0x98, 0x10b);

        let section = 0x98 + 96;
        bytes[section..section + 5].copy_from_slice(b".data");
        put_u32(&mut bytes, section + 8, 0x600);
        put_u32(&mut bytes, section + 12, 0x1000);
        put_u32(&mut bytes, section + 16, raw_size);
        put_u32(&mut bytes, section + 20, raw_offset);
        put_u32(&mut bytes, section + 36, 0xc0000040);
        bytes[raw_offset as usize..raw_offset as usize + raw_size.min(4) as usize]
            .copy_from_slice(b"DATA");
        bytes
    }

    #[test]
    fn validates_file_extent_against_selected_slice() {
        assert_eq!(validated_file_offset(16, 0x4000, 4, 12).unwrap(), 0x4004);
        assert!(validated_file_offset(16, 0x4000, 8, 12).is_err());
    }

    #[test]
    fn initialized_prefix_excludes_virtual_zero_fill_tail() {
        let bytes = pe_with_virtual_tail(512, 4);
        let ranges = coverage_ranges(&bytes, 0).expect("parse PE coverage");
        let initialized = ranges
            .iter()
            .find(|range| range.initialized)
            .expect("initialized section prefix");
        let zero_fill = ranges
            .iter()
            .find(|range| !range.initialized)
            .expect("virtual zero-fill tail");

        assert_eq!(initialized.address, 0x1000..0x1004);
        assert_eq!(initialized.file_offset, Some(512));
        assert!(initialized.loaded);
        assert_eq!(zero_fill.address, 0x1004..0x1600);
        assert_eq!(zero_fill.file_offset, None);
        assert!(zero_fill.loaded);
        let file_ranges = ranges
            .iter()
            .filter_map(|range| {
                range
                    .file_offset
                    .map(|offset| (range.address.clone(), offset))
            })
            .collect::<Vec<_>>();
        assert_eq!(read(&bytes, &file_ranges, 0, 0x1000, 4), b"DATA");
        assert!(read(&bytes, &file_ranges, 0, 0x1004, 4).is_empty());
    }

    #[test]
    fn mapped_ranges_are_segment_authority() {
        let bytes = pe_with_virtual_tail(512, 4);
        let ranges = mapped_ranges(&bytes).expect("parse PE mappings");

        assert!(ranges.iter().any(|range| range.contains(&0x1000)));
        assert!(!ranges.iter().any(|range| range.contains(&0x0)));
    }

    #[test]
    fn coverage_rejects_file_extent_outside_admitted_bytes() {
        let bytes = pe_with_virtual_tail(1000, 32);
        let error = coverage_ranges(&bytes, 0).expect_err("section must exceed file bytes");
        assert!(
            error
                .to_string()
                .contains("file extent exceeds the selected image bytes")
        );
    }

    #[test]
    fn reads_selected_slice_bytes_through_original_file_offsets() {
        let selected = [0xaa, 0xbb, 0xcc];
        let ranges = [(0x1000..0x1003, 0x4000_usize)];

        assert_eq!(read(&selected, &ranges, 0x4000, 0x1000, 3), selected);
        assert_eq!(read(&selected, &ranges, 0x4000, 0x1002, 1), [0xcc]);
        assert!(read(&selected, &ranges, 0x4000, 0x1003, 1).is_empty());
    }
}
