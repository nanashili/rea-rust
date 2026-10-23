//! Read-only ELF32 MIPS shared-image relocation facts.
//!
//! This module reports only declarations that can be mapped unambiguously from
//! PT_LOAD and PT_DYNAMIC.  Unsupported or incomplete declarations remain an
//! error for the caller to represent as unavailable evidence.

use std::fmt;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const SHT_REL: u32 = 9;
const DT_PLTREL: u32 = 20;
const DT_PLTRELSZ: u32 = 2;
const DT_JMPREL: u32 = 23;
const DT_REL: u32 = 17;
const DT_RELSZ: u32 = 18;
const DT_RELENT: u32 = 19;
const DYNAMIC_ENTRY_SIZE: usize = 8;
const PROGRAM_HEADER_SIZE: usize = 32;
const REL_ENTRY_SIZE: usize = 8;
const GNU_ATTRIBUTES_FORMAT_VERSION: u8 = 0x41;
const GNU_ATTRIBUTES_FILE_SCOPE: u32 = 1;
const GNU_MIPS_ABI_FP: u32 = 4;
const GNU_MIPS_ABI_MSA: u32 = 8;

/// File-scope GNU MIPS attributes retained without interpreting their ABI
/// meaning. `None` means the file did not declare the corresponding tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GnuAttributes {
    pub fp_abi: Option<u32>,
    pub msa: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GnuAttributesError(pub String);

impl fmt::Display for GnuAttributesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Parse the bounded file-scope GNU attribute section from an ELF image.
///
/// This accepts only the declarations that the TypeScript metadata reader
/// owns. Other vendors, scopes, and tags are rejected so their values remain
/// unknown instead of being silently discarded.
pub fn parse_gnu_attributes(
    bytes: &[u8],
    little_endian: bool,
) -> Result<GnuAttributes, GnuAttributesError> {
    if bytes.first().copied() != Some(GNU_ATTRIBUTES_FORMAT_VERSION) {
        return Err(attribute_error(
            "unsupported MIPS GNU attribute section format version",
        ));
    }

    let mut position = 1;
    let mut vendor_seen = false;
    let mut fp_abi = None;
    let mut msa = None;

    while position < bytes.len() {
        let length = read_attribute_u32(bytes, position, little_endian)? as usize;
        let end = position
            .checked_add(length)
            .ok_or_else(|| attribute_error("MIPS GNU attribute subsection length overflows"))?;
        if length < 4 || end > bytes.len() {
            return Err(attribute_error(
                "MIPS GNU attribute subsection length does not fit the section",
            ));
        }

        let vendor_start = position + 4;
        let vendor_end = bytes[vendor_start..end]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| vendor_start + offset)
            .ok_or_else(|| attribute_error("unterminated MIPS GNU attribute vendor name"))?;
        if &bytes[vendor_start..vendor_end] != b"gnu" {
            return Err(attribute_error(
                "MIPS ELF declares non-GNU vendor attributes that REA does not inspect",
            ));
        }
        if vendor_seen {
            return Err(attribute_error(
                "duplicate MIPS GNU attribute vendor subsections",
            ));
        }
        vendor_seen = true;

        let mut cursor = vendor_end + 1;
        while cursor < end {
            let scope_start = cursor;
            let (scope, next) = read_uleb(bytes, cursor, end)?;
            if scope != GNU_ATTRIBUTES_FILE_SCOPE {
                return Err(attribute_error(
                    "MIPS GNU attributes scoped to sections or symbols are not inspected by REA",
                ));
            }
            let scope_length = read_attribute_u32(bytes, next, little_endian)? as usize;
            let scope_end = scope_start
                .checked_add(scope_length)
                .ok_or_else(|| attribute_error("MIPS GNU attribute scope length overflows"))?;
            if scope_length < next + 4 - scope_start || scope_end > end {
                return Err(attribute_error(
                    "MIPS GNU attribute scope length does not fit its subsection",
                ));
            }

            cursor = next + 4;
            while cursor < scope_end {
                let (tag, value_start) = read_uleb(bytes, cursor, scope_end)?;
                let (value, value_end) = read_uleb(bytes, value_start, scope_end)?;
                match tag {
                    GNU_MIPS_ABI_FP => {
                        if fp_abi.replace(value).is_some() {
                            return Err(attribute_error(
                                "duplicate MIPS GNU floating-point ABI attributes",
                            ));
                        }
                    }
                    GNU_MIPS_ABI_MSA => {
                        if msa.replace(value).is_some() {
                            return Err(attribute_error("duplicate MIPS GNU MSA ABI attributes"));
                        }
                    }
                    other => {
                        return Err(attribute_error(&format!(
                            "MIPS ELF declares GNU attribute tag {other}, which REA does not inspect",
                        )));
                    }
                }
                cursor = value_end;
            }
            cursor = scope_end;
        }

        position = end;
    }

    Ok(GnuAttributes { fp_abi, msa })
}

fn attribute_error(message: &str) -> GnuAttributesError {
    GnuAttributesError(message.to_owned())
}

fn read_attribute_u32(
    bytes: &[u8],
    offset: usize,
    little_endian: bool,
) -> Result<u32, GnuAttributesError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| attribute_error("MIPS GNU attribute integer offset overflows"))?;
    let data = bytes
        .get(offset..end)
        .ok_or_else(|| attribute_error("truncated MIPS GNU attribute integer"))?;
    Ok(if little_endian {
        u32::from_le_bytes(data.try_into().expect("four-byte attribute integer"))
    } else {
        u32::from_be_bytes(data.try_into().expect("four-byte attribute integer"))
    })
}

fn read_uleb(bytes: &[u8], offset: usize, end: usize) -> Result<(u32, usize), GnuAttributesError> {
    let mut value = 0u32;
    for index in 0..5 {
        let at = offset
            .checked_add(index)
            .ok_or_else(|| attribute_error("MIPS GNU attribute value offset overflows"))?;
        if at >= end {
            break;
        }
        let byte = bytes[at];
        let shift = index * 7;
        let part = u32::from(byte & 0x7f)
            .checked_shl(shift as u32)
            .ok_or_else(|| attribute_error("MIPS GNU attribute value overflows"))?;
        value = value
            .checked_add(part)
            .ok_or_else(|| attribute_error("MIPS GNU attribute value overflows"))?;
        if byte & 0x80 == 0 {
            return Ok((value, at + 1));
        }
    }
    Err(attribute_error("malformed MIPS GNU attribute value"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationSection {
    pub section_type: u32,
    pub file_offset: u32,
    pub size: u32,
    pub entry_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedLoadFacts {
    pub relocation_count: u32,
    pub relocation_types: Vec<u32>,
    pub symbol_relative_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedLoadError(pub String);

impl fmt::Display for SharedLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Inspect ELF32 MIPS program-header and dynamic relocation declarations.
///
/// `program_headers` is the already validated ELF32 program-header table. The
/// complete file bytes are required so every dynamic and relocation record is
/// examined before facts are admitted. Section declarations are supplied by
/// the owning ELF metadata reader because section-table coverage is a separate
/// source of completeness.
pub fn inspect(
    program_headers: &[u8],
    file_bytes: &[u8],
    little_endian: bool,
    sections: &[RelocationSection],
) -> Result<SharedLoadFacts, SharedLoadError> {
    if !program_headers.len().is_multiple_of(PROGRAM_HEADER_SIZE) {
        return Err(error("truncated MIPS program header table"));
    }

    let mut loads = Vec::new();
    let mut dynamic = None;

    for header in program_headers.chunks_exact(PROGRAM_HEADER_SIZE) {
        let kind = read_u32(header, 0, little_endian);
        let file_offset = read_u32(header, 4, little_endian) as u64;
        let address = read_u32(header, 8, little_endian) as u64;
        let file_size = read_u32(header, 16, little_endian) as u64;
        let memory_size = read_u32(header, 20, little_endian) as u64;

        if kind == PT_LOAD {
            if file_offset + file_size > file_bytes.len() as u64
                || file_size > memory_size
                || address + memory_size > 0x1_0000_0000
            {
                return Err(error("invalid or incomplete MIPS PT_LOAD range"));
            }
            loads.push(LoadRange {
                file_offset,
                address,
                file_size,
                memory_size,
            });
        } else if kind == PT_DYNAMIC {
            if dynamic.is_some() {
                return Err(error("duplicate MIPS PT_DYNAMIC tables"));
            }
            dynamic = Some(DynamicRange {
                file_offset,
                address,
                size: file_size,
            });
        }
    }

    let dynamic = dynamic.ok_or_else(|| error("MIPS shared image has no PT_DYNAMIC table"))?;
    if dynamic.size == 0 || dynamic.size % DYNAMIC_ENTRY_SIZE as u64 != 0 {
        return Err(error("invalid MIPS ELF32 dynamic table size"));
    }
    if dynamic.file_offset + dynamic.size > file_bytes.len() as u64 {
        return Err(error("MIPS PT_DYNAMIC range extends beyond the file"));
    }

    loads.sort_by_key(|load| load.address);
    for pair in loads.windows(2) {
        if pair[1].address < pair[0].address + pair[0].memory_size {
            return Err(error(
                "overlapping MIPS PT_LOAD memory ranges require separate mapping verification",
            ));
        }
    }
    let mapping = unique_mapping(&loads, dynamic.address, dynamic.size, true)
        .ok_or_else(|| error("MIPS PT_DYNAMIC has no unique matching file-backed PT_LOAD range"))?;
    if mapping.file_offset != dynamic.file_offset {
        return Err(error(
            "MIPS PT_DYNAMIC has no unique matching file-backed PT_LOAD range",
        ));
    }

    let mut tags = [None; 9];
    let mut terminated = false;
    for entry in file_bytes
        [dynamic.file_offset as usize..(dynamic.file_offset + dynamic.size) as usize]
        .chunks_exact(DYNAMIC_ENTRY_SIZE)
    {
        let tag = read_u32(entry, 0, little_endian);
        if tag == 0 {
            terminated = true;
            break;
        }
        if let Some(index) = relevant_tag_index(tag) {
            if tags[index].is_some() {
                return Err(error(&format!("duplicate MIPS dynamic tag {tag}")));
            }
            tags[index] = Some(read_u32(entry, 4, little_endian));
        }
    }
    if !terminated {
        return Err(error("MIPS dynamic table has no DT_NULL terminator"));
    }
    if [DT_PLTRELSZ, 7, 8, 9, DT_JMPREL]
        .iter()
        .filter_map(|tag| relevant_tag_index(*tag).and_then(|index| tags[index]))
        .any(|value| value != 0)
    {
        return Err(error(
            "MIPS shared RELA or PLT relocation declarations require separate verification",
        ));
    }

    let address = tag_value(&tags, DT_REL);
    let size = tag_value(&tags, DT_RELSZ);
    let stride = tag_value(&tags, DT_RELENT);
    if address.is_none() && size.is_none() && stride.is_none() {
        return empty_relocations(sections, 0, 0);
    }
    let (address, size) = match (address, size, stride) {
        (Some(address), Some(size), Some(entry_size))
            if entry_size == REL_ENTRY_SIZE as u32 && size % REL_ENTRY_SIZE as u32 == 0 =>
        {
            (address as u64, size as u64)
        }
        _ => {
            return Err(error(
                "incomplete or invalid MIPS DT_REL/DT_RELSZ/DT_RELENT declaration",
            ));
        }
    };
    if size == 0 {
        return empty_relocations(sections, 0, 0);
    }
    let mapping = unique_mapping(&loads, address, size, true).ok_or_else(|| {
        error("MIPS DT_REL range has no unique complete file-backed PT_LOAD mapping")
    })?;
    let file_offset = mapping.file_offset;
    if file_offset + size > file_bytes.len() as u64 {
        return Err(error(
            "MIPS DT_REL range has no unique complete file-backed PT_LOAD mapping",
        ));
    }
    empty_relocations(sections, file_offset as u32, size as u32)?;

    let mut relocation_types = Vec::new();
    let mut symbol_relative_count = 0;
    for entry in
        file_bytes[file_offset as usize..(file_offset + size) as usize].chunks_exact(REL_ENTRY_SIZE)
    {
        let relocation_address = read_u32(entry, 0, little_endian) as u64;
        let info = read_u32(entry, 4, little_endian);
        let relocation_type = info & 0xff;
        if relocation_type == 3 {
            if unique_mapping(&loads, relocation_address, 4, false).is_none() {
                return Err(error(
                    "MIPS REL32 destination has no unique complete PT_LOAD memory range",
                ));
            }
            if info >> 8 != 0 {
                symbol_relative_count += 1;
            }
        }
        if !relocation_types.contains(&relocation_type) {
            relocation_types.push(relocation_type);
        }
    }
    relocation_types.sort_unstable();
    Ok(SharedLoadFacts {
        relocation_count: (size / REL_ENTRY_SIZE as u64) as u32,
        relocation_types,
        symbol_relative_count,
    })
}

#[derive(Clone, Copy)]
struct LoadRange {
    file_offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
}

#[derive(Clone, Copy)]
struct DynamicRange {
    file_offset: u64,
    address: u64,
    size: u64,
}

fn unique_mapping(
    loads: &[LoadRange],
    address: u64,
    length: u64,
    file_backed: bool,
) -> Option<LoadRange> {
    let mut found = None;
    for load in loads {
        let capacity = if file_backed {
            load.file_size
        } else {
            load.memory_size
        };
        if address >= load.address && address - load.address <= capacity.checked_sub(length)? {
            if found.is_some() {
                return None;
            }
            found = Some(LoadRange {
                file_offset: load.file_offset + address - load.address,
                ..*load
            });
        }
    }
    found
}

fn empty_relocations(
    sections: &[RelocationSection],
    file_offset: u32,
    size: u32,
) -> Result<SharedLoadFacts, SharedLoadError> {
    for section in sections {
        if section.size != 0
            && (section.section_type != SHT_REL
                || section.entry_size != REL_ENTRY_SIZE as u32
                || section.file_offset != file_offset
                || section.size != size)
        {
            return Err(error(
                "MIPS section relocation declarations outside the dynamic REL table require separate verification",
            ));
        }
    }
    if sections.iter().filter(|section| section.size != 0).count() > 1 {
        return Err(error(
            "duplicate MIPS section relocation declarations require separate verification",
        ));
    }
    Ok(SharedLoadFacts {
        relocation_count: 0,
        relocation_types: Vec::new(),
        symbol_relative_count: 0,
    })
}

fn relevant_tag_index(tag: u32) -> Option<usize> {
    [
        DT_PLTRELSZ,
        7,
        8,
        9,
        DT_REL,
        DT_RELSZ,
        DT_RELENT,
        DT_PLTREL,
        DT_JMPREL,
    ]
    .iter()
    .position(|candidate| *candidate == tag)
}

fn tag_value(tags: &[Option<u32>; 9], tag: u32) -> Option<u32> {
    relevant_tag_index(tag).and_then(|index| tags[index])
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> u32 {
    let bytes = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

fn error(message: &str) -> SharedLoadError {
    SharedLoadError(message.to_owned())
}
