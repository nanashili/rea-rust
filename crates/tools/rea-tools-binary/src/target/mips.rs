//! ELF32 MIPS ABI, GNU-attribute and shared-load inspection from the open file.
//!
//! Ports `src/application/MipsElfMetadata.ts` (`readMipsElfMetadata`),
//! `src/application/MipsGnuAttributes.ts` (`parseMipsGnuAttributes`,
//! `MIPS_GNU_ATTRIBUTES_MAX_BYTES`) and `src/application/MipsElfSharedLoad.ts`
//! (`readMipsElfSharedLoad`).
//!
//! The caller supplies a bounded positioned reader and a cancellation check so
//! that the tagged cancellation error is preserved exactly as the TS code does.

use serde_json::{Map, Value, json};

use super::elf::read_elf_fixed_header;
use super::header::{read_u16, read_u32};

/// Base ELF family facts recovered by the header parser (`parsed.value.mips`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct MipsBase {
    pub elf_class: u8,
    pub little_endian: bool,
    pub elf_type: u16,
    pub flags: u32,
}

/// TS `MipsElfInspection`. `abi_flags`/`gnu_attributes` are `Value::Null` when
/// no record was observed (TS `null`), or the parsed object.
pub(crate) struct MipsInspection {
    pub abi_flags: Value,
    pub gnu_attributes: Value,
    pub limitations: Vec<String>,
    pub shared_load: Option<Value>,
}

const SHT_GNU_ATTRIBUTES: u32 = 0x6fff_fff5;
const MIPS_GNU_ATTRIBUTES_MAX_BYTES: u32 = 4096;

/// The caller's cancellation-aware, bounded positioned reader.
///
/// `read(offset, length, label) -> Result<bytes, reason>`; it must enforce the
/// TS "lies outside the file" / "truncated" checks and run the cancellation
/// check before and after each physical read.
pub(crate) trait RangeReader {
    fn file_size(&self) -> u64;
    fn read(&self, offset: u64, length: u64, label: &str) -> Result<Vec<u8>, String>;
    /// Returns `Err` with the tagged cancellation when cancelled.
    fn check_cancelled(&self) -> Result<(), String>;
}

/// TS `readMipsElfMetadata(handle, metadata, checkCancelled)`.
pub(crate) fn read_mips_elf_metadata<R: RangeReader>(
    reader: &R,
    base: MipsBase,
) -> Result<MipsInspection, String> {
    reader.check_cancelled()?;
    if base.elf_class != 32 {
        return Err("MIPS ABI record inspection currently supports ELF32 only".to_string());
    }
    let file_size = reader.file_size();
    reader.check_cancelled()?;
    let little = base.little_endian;
    let u16r = |data: &[u8], offset: usize| read_u16(data, offset, little);
    let u32r = |data: &[u8], offset: usize| read_u32(data, offset, little);

    let header = reader.read(0, 52, "ELF32 header")?;
    let fixed = read_elf_fixed_header(&header, file_size)?;
    if fixed.elf_class != 32
        || fixed.little_endian != little
        || fixed.machine != 8
        || u16r(&header, 16) as u16 != base.elf_type
        || u32r(&header, 36) != base.flags
    {
        return Err("MIPS ELF header no longer matches the resolved identity".to_string());
    }
    if fixed.header_size != 52 {
        return Err("invalid MIPS ELF32 version or header size".to_string());
    }

    struct TableSpec {
        label: &'static str,
        offset: u64,
        count: u32,
        stride: u16,
        entry_size: u32,
        type_offset: usize,
        data_offset: usize,
        size_offset: usize,
        record_type: u32,
        optional: bool,
    }
    let tables = [
        TableSpec {
            label: "program header table",
            offset: u32r(&header, 28) as u64,
            count: u16r(&header, 44) as u32,
            stride: u16r(&header, 42),
            entry_size: 32,
            type_offset: 0,
            data_offset: 4,
            size_offset: 16,
            record_type: 0x7000_0003, // PT_MIPS_ABIFLAGS
            optional: false,
        },
        TableSpec {
            label: "section header table",
            offset: u32r(&header, 32) as u64,
            count: u16r(&header, 48) as u32,
            stride: u16r(&header, 46),
            entry_size: 40,
            type_offset: 4,
            data_offset: 16,
            size_offset: 20,
            record_type: 0x7000_002a, // SHT_MIPS_ABIFLAGS
            optional: true,
        },
    ];
    if u16r(&header, 44) == 0xffff || u16r(&header, 48) >= 0xff00 {
        return Err("extended or reserved MIPS ELF table numbering is unsupported".to_string());
    }

    let mut record: Option<Vec<u8>> = None;
    let mut shared_load: Option<Value> = None;
    let mut program_headers: Option<Vec<u8>> = None;
    let mut relocation_sections: Vec<RelocationSection> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();
    let mut gnu_attributes: Option<Value> = None;
    let mut gnu_attributes_seen = false;

    for table in &tables {
        if table.count == 0 {
            if table.offset != 0 {
                return Err(format!(
                    "unsupported extended or inconsistent MIPS {}",
                    table.label
                ));
            }
            continue;
        }
        if table.offset < 52 || table.stride as u32 != table.entry_size {
            return Err(format!("invalid MIPS {} offset or entry size", table.label));
        }
        let count = if table.optional {
            let fits = if file_size >= table.offset {
                ((file_size - table.offset) / table.entry_size as u64) as u32
            } else {
                0
            };
            std::cmp::min(table.count, fits)
        } else {
            table.count
        };
        if count < table.count {
            limitations.push(format!(
                "MIPS {} at file offset {} extends beyond the captured file: examined {} of {} complete headers. ABI declarations in unavailable headers remain unknown.",
                table.label, table.offset, count, table.count
            ));
        }
        if count == 0 {
            continue;
        }
        let contents = reader.read(
            table.offset,
            count as u64 * table.entry_size as u64,
            table.label,
        )?;
        if !table.optional && base.elf_type == 3 {
            program_headers = Some(contents.clone());
        }
        let mut found = false;
        for i in 0..count as usize {
            reader.check_cancelled()?;
            let position = i * table.entry_size as usize;
            let entry_type = u32r(&contents, position + table.type_offset);
            if table.optional && entry_type == SHT_GNU_ATTRIBUTES {
                if gnu_attributes_seen {
                    return Err("duplicate MIPS GNU attribute sections".to_string());
                }
                gnu_attributes_seen = true;
                let size = u32r(&contents, position + 20);
                if size == 0 || size > MIPS_GNU_ATTRIBUTES_MAX_BYTES {
                    return Err(format!(
                        "MIPS GNU attribute section size {size} is outside REA's inspected bound of {MIPS_GNU_ATTRIBUTES_MAX_BYTES} bytes"
                    ));
                }
                let section = reader.read(
                    u32r(&contents, position + 16) as u64,
                    size as u64,
                    "GNU attribute section",
                )?;
                gnu_attributes = Some(parse_mips_gnu_attributes(&section, little)?);
                continue;
            }
            if base.elf_type == 3 && table.optional && (entry_type == 4 || entry_type == 9) {
                relocation_sections.push(RelocationSection {
                    section_type: entry_type,
                    offset: u32r(&contents, position + 16),
                    size: u32r(&contents, position + 20),
                    entry_size: u32r(&contents, position + 36),
                });
            }
            if entry_type != table.record_type {
                continue;
            }
            if found {
                return Err(format!("duplicate MIPS ABI records in {}", table.label));
            }
            found = true;
            let offset = u32r(&contents, position + table.data_offset);
            let size = u32r(&contents, position + table.size_offset);
            if size != 24 {
                return Err("unsupported MIPS ABI record size; expected 24 bytes".to_string());
            }
            let candidate = reader.read(offset as u64, 24, "ABI record")?;
            if let Some(existing) = &record {
                if existing != &candidate {
                    return Err("conflicting MIPS program/section ABI declarations".to_string());
                }
            }
            record = Some(candidate);
        }
    }

    if base.elf_type == 3 {
        if let Some(program_headers) = &program_headers {
            if !limitations.is_empty() {
                shared_load = Some(json!({
                    "status": "unavailable",
                    "reason": format!(
                        "MIPS shared-image relocation declaration sources are incomplete. {}",
                        limitations.join(" ")
                    ),
                }));
            } else {
                match read_mips_elf_shared_load(
                    program_headers,
                    little,
                    file_size,
                    reader,
                    &relocation_sections,
                ) {
                    Ok(value) => shared_load = Some(value),
                    Err(reason) => {
                        shared_load = Some(json!({
                            "status": "unavailable",
                            "reason": reason,
                        }));
                    }
                }
            }
        }
    }

    let shared = if base.elf_type == 3 {
        Some(shared_load.unwrap_or_else(|| {
            json!({
                "status": "unavailable",
                "reason": "MIPS shared image has no inspected program header table",
            })
        }))
    } else {
        None
    };

    let gnu_attributes_value = gnu_attributes.unwrap_or(Value::Null);

    let record = match record {
        Some(record) => record,
        None => {
            return Ok(MipsInspection {
                abi_flags: Value::Null,
                gnu_attributes: gnu_attributes_value,
                limitations,
                shared_load: shared,
            });
        }
    };

    let abi_flags = json!({
        "version": u16r(&record, 0),
        "isaLevel": record[2],
        "isaRevision": record[3],
        "gprSize": record[4],
        "cpr1Size": record[5],
        "cpr2Size": record[6],
        "fpAbi": record[7],
        "isaExtension": u32r(&record, 8),
        "ases": u32r(&record, 12),
        "flags1": u32r(&record, 16),
        "flags2": u32r(&record, 20),
    });
    // Conflict check against GNU floating-point ABI.
    if let Value::Object(attributes) = &gnu_attributes_value {
        if let Some(fp_abi) = attributes.get("fpAbi").and_then(Value::as_u64) {
            let record_fp = record[7] as u64;
            if fp_abi != 0 && fp_abi != record_fp {
                return Err(
                    "conflicting MIPS ABI flags and GNU floating-point ABI declarations"
                        .to_string(),
                );
            }
        }
    }

    Ok(MipsInspection {
        abi_flags,
        gnu_attributes: gnu_attributes_value,
        limitations,
        shared_load: shared,
    })
}

// ----- MipsGnuAttributes.ts -----

const FORMAT_VERSION: u8 = 0x41;
const TAG_FILE: u64 = 1;
const TAG_GNU_MIPS_ABI_FP: u64 = 4;
const TAG_GNU_MIPS_ABI_MSA: u64 = 8;

/// TS `parseMipsGnuAttributes(bytes, littleEndian)` -> `{ fpAbi, msa }`.
fn parse_mips_gnu_attributes(bytes: &[u8], little: bool) -> Result<Value, String> {
    if bytes.is_empty() || bytes[0] != FORMAT_VERSION {
        return Err("unsupported MIPS GNU attribute section format version".to_string());
    }
    let read_u32v = |offset: usize| -> u32 { read_u32(bytes, offset, little) };
    // ULEB128 returning (value, next) with the TS 5-byte / <=0xffffffff bound.
    let read_uleb = |offset: usize, end: usize| -> Option<(u64, usize)> {
        let mut value: u64 = 0;
        let mut index = 0usize;
        while index < 5 && offset + index < end {
            let byte = bytes[offset + index];
            value += ((byte & 0x7f) as u64) * (1u64 << (7 * index));
            if byte & 0x80 == 0 {
                return if value <= 0xffff_ffff {
                    Some((value, offset + index + 1))
                } else {
                    None
                };
            }
            index += 1;
        }
        None
    };

    let mut fp_abi: Option<u64> = None;
    let mut msa: Option<u64> = None;
    let mut vendor_seen = false;
    let mut position = 1usize;
    while position < bytes.len() {
        if bytes.len() - position < 4 {
            return Err("truncated MIPS GNU attribute subsection length".to_string());
        }
        let length = read_u32v(position) as usize;
        if length < 4 || length > bytes.len() - position {
            return Err(
                "MIPS GNU attribute subsection length does not fit the section".to_string(),
            );
        }
        let end = position + length;
        let vendor_end = bytes[position + 4..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|p| p + position + 4);
        let vendor_end = match vendor_end {
            Some(vendor_end) if vendor_end < end => vendor_end,
            _ => return Err("unterminated MIPS GNU attribute vendor name".to_string()),
        };
        if &bytes[position + 4..vendor_end] != b"gnu" {
            return Err(
                "MIPS ELF declares non-GNU vendor attributes that REA does not inspect".to_string(),
            );
        }
        if vendor_seen {
            return Err("duplicate MIPS GNU attribute vendor subsections".to_string());
        }
        vendor_seen = true;

        let mut cursor = vendor_end + 1;
        while cursor < end {
            let scope_start = cursor;
            let scope = read_uleb(cursor, end)
                .ok_or_else(|| "malformed MIPS GNU attribute scope tag".to_string())?;
            if scope.0 != TAG_FILE {
                return Err(
                    "MIPS GNU attributes scoped to sections or symbols are not inspected by REA"
                        .to_string(),
                );
            }
            if end - scope.1 < 4 {
                return Err("truncated MIPS GNU attribute scope length".to_string());
            }
            let scope_length = read_u32v(scope.1) as usize;
            if scope_length < scope.1 + 4 - scope_start || scope_length > end - scope_start {
                return Err(
                    "MIPS GNU attribute scope length does not fit its subsection".to_string(),
                );
            }
            let scope_end = scope_start + scope_length;
            cursor = scope.1 + 4;
            while cursor < scope_end {
                let tag = read_uleb(cursor, scope_end)
                    .ok_or_else(|| "malformed MIPS GNU attribute tag".to_string())?;
                if tag.0 != TAG_GNU_MIPS_ABI_FP && tag.0 != TAG_GNU_MIPS_ABI_MSA {
                    return Err(format!(
                        "MIPS ELF declares GNU attribute tag {}, which REA does not inspect",
                        tag.0
                    ));
                }
                let value = read_uleb(tag.1, scope_end)
                    .ok_or_else(|| "malformed MIPS GNU attribute value".to_string())?;
                if tag.0 == TAG_GNU_MIPS_ABI_FP {
                    if fp_abi.is_some() {
                        return Err("duplicate MIPS GNU floating-point ABI attributes".to_string());
                    }
                    fp_abi = Some(value.0);
                } else {
                    if msa.is_some() {
                        return Err("duplicate MIPS GNU MSA ABI attributes".to_string());
                    }
                    msa = Some(value.0);
                }
                cursor = value.1;
            }
            cursor = scope_end;
        }
        position = end;
    }
    Ok(json!({
        "fpAbi": fp_abi,
        "msa": msa,
    }))
}

// ----- MipsElfSharedLoad.ts -----

struct RelocationSection {
    section_type: u32,
    offset: u32,
    size: u32,
    entry_size: u32,
}

struct LoadRange {
    offset: u64,
    address: u64,
    size: u64,
    memory_size: u64,
}

/// TS `readMipsElfSharedLoad(programHeaders, little, fileSize, read, check, sections)`.
fn read_mips_elf_shared_load<R: RangeReader>(
    program_headers: &[u8],
    little: bool,
    file_size: u64,
    reader: &R,
    sections: &[RelocationSection],
) -> Result<Value, String> {
    let u32r = |data: &[u8], offset: usize| read_u32(data, offset, little) as u64;
    let mut loads: Vec<LoadRange> = Vec::new();
    let mut dynamic: Option<(u64, u64, u64)> = None; // offset, address, size
    let mut position = 0usize;
    while position < program_headers.len() {
        reader.check_cancelled()?;
        let entry_type = u32r(program_headers, position);
        let offset = u32r(program_headers, position + 4);
        let size = u32r(program_headers, position + 16);
        if entry_type == 1 {
            let address = u32r(program_headers, position + 8);
            let memory_size = u32r(program_headers, position + 20);
            if offset > file_size.saturating_sub(size)
                || (file_size < size)
                || size > memory_size
                || address + memory_size > 0x1_0000_0000
            {
                return Err("invalid or incomplete MIPS PT_LOAD range".to_string());
            }
            loads.push(LoadRange {
                offset,
                address,
                size,
                memory_size,
            });
        }
        if entry_type == 2 {
            if dynamic.is_some() {
                return Err("duplicate MIPS PT_DYNAMIC tables".to_string());
            }
            dynamic = Some((offset, u32r(program_headers, position + 8), size));
        }
        position += 32;
    }
    let (dyn_offset, dyn_address, dyn_size) =
        dynamic.ok_or_else(|| "MIPS shared image has no PT_DYNAMIC table".to_string())?;
    if dyn_size == 0 || dyn_size % 8 != 0 {
        return Err("invalid MIPS ELF32 dynamic table size".to_string());
    }
    if dyn_offset > file_size.saturating_sub(dyn_size) || file_size < dyn_size {
        return Err("MIPS PT_DYNAMIC range extends beyond the file".to_string());
    }
    let mut ranges: Vec<&LoadRange> = loads.iter().filter(|load| load.memory_size > 0).collect();
    ranges.sort_by(|left, right| left.address.cmp(&right.address));
    for i in 1..ranges.len() {
        reader.check_cancelled()?;
        let previous = ranges[i - 1];
        if ranges[i].address < previous.address + previous.memory_size {
            return Err(
                "overlapping MIPS PT_LOAD memory ranges require separate mapping verification"
                    .to_string(),
            );
        }
    }
    // Binary search mirroring TS `mapped`.
    let mapped = |address: u64, length: u64, file_backed: bool| -> Option<&LoadRange> {
        let mut low = 0usize;
        let mut high = ranges.len();
        while low < high {
            let middle = (low + high) / 2;
            if ranges[middle].address <= address {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low == 0 {
            return None;
        }
        let range = ranges[low - 1];
        let span = if file_backed {
            range.size
        } else {
            range.memory_size
        };
        if address >= range.address && address - range.address <= span.saturating_sub(length) {
            Some(range)
        } else {
            None
        }
    };
    let dynamic_mapping = mapped(dyn_address, dyn_size, true);
    match dynamic_mapping {
        Some(mapping) if mapping.offset + dyn_address - mapping.address == dyn_offset => {}
        _ => {
            return Err(
                "MIPS PT_DYNAMIC has no unique matching file-backed PT_LOAD range".to_string(),
            );
        }
    }

    let chunk_bytes: u64 = 64 * 1024;
    let relevant = [2u64, 7, 8, 9, 17, 18, 19, 20, 23];
    let mut tags: Map<String, Value> = Map::new();
    let mut tag_values: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let _ = &mut tags;
    let mut terminated = false;
    let mut offset = 0u64;
    while offset < dyn_size && !terminated {
        let chunk = reader.read(
            dyn_offset + offset,
            std::cmp::min(chunk_bytes, dyn_size - offset),
            "dynamic table",
        )?;
        let mut position = 0usize;
        while position < chunk.len() {
            reader.check_cancelled()?;
            let tag = u32r(&chunk, position);
            if tag == 0 {
                terminated = true;
                break;
            }
            if relevant.contains(&tag) {
                if tag_values.contains_key(&tag) {
                    return Err(format!("duplicate MIPS dynamic tag {tag}"));
                }
                tag_values.insert(tag, u32r(&chunk, position + 4));
            }
            position += 8;
        }
        offset += chunk_bytes;
    }
    if !terminated {
        return Err("MIPS dynamic table has no DT_NULL terminator".to_string());
    }
    if [2u64, 7, 8, 9, 23]
        .iter()
        .any(|tag| tag_values.get(tag).copied().unwrap_or(0) != 0)
    {
        return Err(
            "MIPS shared RELA or PLT relocation declarations require separate verification"
                .to_string(),
        );
    }
    let address = tag_values.get(&17).copied();
    let size = tag_values.get(&18).copied();
    let stride = tag_values.get(&19).copied();

    let check_sections = |offset: u64, length: u64| -> Option<String> {
        let mut observed = 0usize;
        for section in sections {
            if reader.check_cancelled().is_err() {
                // Preserve cancellation as a reason string; the resolve-level
                // cancellation check also fires, so the tagged error wins.
            }
            if section.size == 0 {
                continue;
            }
            if section.section_type != 9
                || section.entry_size != 8
                || section.offset as u64 != offset
                || section.size as u64 != length
            {
                return Some(
                    "MIPS section relocation declarations outside the dynamic REL table require separate verification"
                        .to_string(),
                );
            }
            observed += 1;
        }
        if observed > 1 {
            Some(
                "duplicate MIPS section relocation declarations require separate verification"
                    .to_string(),
            )
        } else {
            None
        }
    };

    let empty_relocations = |check: &dyn Fn(u64, u64) -> Option<String>| -> Result<Value, String> {
        match check(0, 0) {
            None => Ok(json!({
                "status": "complete",
                "relocationCount": 0,
                "relocationTypes": [],
                "symbolRelativeCount": 0,
            })),
            Some(reason) => Err(reason),
        }
    };

    if address.is_none() && size.is_none() && stride.is_none() {
        return empty_relocations(&check_sections);
    }
    let (address, size) = match (address, size, stride) {
        (Some(address), Some(size), Some(8)) if size % 8 == 0 => (address, size),
        _ => {
            return Err(
                "incomplete or invalid MIPS DT_REL/DT_RELSZ/DT_RELENT declaration".to_string(),
            );
        }
    };
    if size == 0 {
        return empty_relocations(&check_sections);
    }
    let mapping = mapped(address, size, true).ok_or_else(|| {
        "MIPS DT_REL range has no unique complete file-backed PT_LOAD mapping".to_string()
    })?;
    let file_offset = mapping.offset + address - mapping.address;
    if let Some(reason) = check_sections(file_offset, size) {
        return Err(reason);
    }
    let mut symbol_relative_count: u64 = 0;
    let mut types: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut offset = 0u64;
    while offset < size {
        let chunk = reader.read(
            file_offset + offset,
            std::cmp::min(chunk_bytes, size - offset),
            "dynamic REL records",
        )?;
        let mut position = 0usize;
        while position < chunk.len() {
            reader.check_cancelled()?;
            let info = u32r(&chunk, position + 4);
            let relocation_type = info & 0xff;
            let relocation_address = u32r(&chunk, position);
            if relocation_type == 3 && mapped(relocation_address, 4, false).is_none() {
                return Err(
                    "MIPS REL32 destination has no unique complete PT_LOAD memory range"
                        .to_string(),
                );
            }
            types.insert(relocation_type);
            if relocation_type == 3 && info >> 8 != 0 {
                symbol_relative_count += 1;
            }
            position += 8;
        }
        offset += chunk_bytes;
    }
    let relocation_types: Vec<Value> = types.into_iter().map(|t| json!(t)).collect();
    Ok(json!({
        "status": "complete",
        "relocationCount": size / 8,
        "relocationTypes": relocation_types,
        "symbolRelativeCount": symbol_relative_count,
    }))
}
