//! Dart AOT ELF decoding over an in-memory image.
//!
//! Compatibility owners: `src/flutter/DartElf.ts`, `src/flutter/ElfLoadMap.ts`
//! and `src/domain/elfFixedHeader.ts`.
//!
//! Numbers follow the TypeScript `BoundedReader`: a 64-bit little-endian read
//! returns `None` when the high 32 bits exceed `0x001fffff`, matching the
//! JavaScript safe-integer cap used there.

use std::collections::{HashMap, HashSet};

use crate::flutter::payload_scan::{SNAPSHOT_HASH_LENGTH, SNAPSHOT_HASH_OFFSET, is_snapshot_hash};

/// JavaScript `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn is_safe_integer(value: u64) -> bool {
    value <= MAX_SAFE_INTEGER
}

/// ELF32 needs 52 bytes, ELF64 needs 64; retain at most this prefix.
pub const ELF_HEADER_MAX_BYTES: usize = 64;

const SHT_DYNSYM: u32 = 11;
const SHF_ALLOC: u64 = 2;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
/// Position-independent executable images carry PT_DYNAMIC.
const ET_DYN: u16 = 3;
const DT_NULL: u64 = 0;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;

/// Bounds-checked little-endian reader over one loaded buffer.
struct BoundedReader<'a> {
    bytes: &'a [u8],
}

impl<'a> BoundedReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn u16(&self, offset: usize) -> Option<u16> {
        self.bytes
            .get(offset..offset + 2)
            .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn u32(&self, offset: usize) -> Option<u32> {
        self.bytes
            .get(offset..offset + 4)
            .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn u64(&self, offset: usize) -> Option<u64> {
        let low = self.u32(offset)? as u64;
        let high = self.u32(offset + 4)? as u64;
        if high > 0x001f_ffff {
            return None;
        }
        Some(high * 0x1_0000_0000 + low)
    }

    fn c_string(&self, offset: usize, table_end: usize) -> Option<String> {
        if offset >= table_end || table_end > self.bytes.len() {
            return None;
        }
        let limit = table_end.min(offset + 257);
        let slice = &self.bytes[offset..limit];
        let end = slice.iter().position(|&byte| byte == 0)?;
        // latin1 decode of the name bytes.
        Some(
            self.bytes[offset..offset + end]
                .iter()
                .map(|&byte| byte as char)
                .collect(),
        )
    }
}

/// A `u16` read used both as width and count.
fn opt_u16_usize(value: Option<u16>) -> Option<usize> {
    value.map(usize::from)
}

#[derive(Clone, Copy)]
pub struct ElfHeader {
    pub is64: bool,
    pub dynamic_fallback: bool,
    pub e_shoff: u64,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_phoff: u64,
    pub e_phentsize: u16,
    pub e_phnum: u16,
}

/// Fixed-header commitments needed by the ELF-table reader.
struct FixedHeader {
    elf_class: u8,
    byte_order_little: bool,
    header_size: u16,
}

/// Port of `readElfFixedHeader` restricted to the fields the Flutter path uses.
fn read_elf_fixed_header(bytes: &[u8], total_bytes: usize) -> Result<FixedHeader, String> {
    if bytes.len() >= 4 && bytes[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        return Err("not an ELF image".into());
    }
    if bytes.len() < 16 {
        return Err("ELF identification is truncated".into());
    }
    let class_byte = bytes[4];
    if class_byte != 1 && class_byte != 2 {
        return Err("unsupported ELF class".into());
    }
    let data_byte = bytes[5];
    if data_byte != 1 && data_byte != 2 {
        return Err("unsupported ELF endianness".into());
    }
    if bytes[6] != 1 {
        return Err("unsupported ELF identification version".into());
    }
    let elf_class: u8 = if class_byte == 1 { 32 } else { 64 };
    let minimum_size: usize = if elf_class == 32 { 52 } else { 64 };
    if !is_safe_integer(total_bytes as u64)
        || total_bytes < bytes.len()
        || total_bytes < minimum_size
        || bytes.len() < minimum_size
    {
        return Err(format!(
            "truncated ELF header: an ELF{elf_class} header needs {minimum_size} bytes; the file has {total_bytes}"
        ));
    }
    let little_endian = data_byte == 1;
    let read_u16 = |offset: usize| -> u16 {
        let slice = &bytes[offset..offset + 2];
        if little_endian {
            u16::from_le_bytes([slice[0], slice[1]])
        } else {
            u16::from_be_bytes([slice[0], slice[1]])
        }
    };
    let read_u32 = |offset: usize| -> u32 {
        let slice = &bytes[offset..offset + 4];
        if little_endian {
            u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
        } else {
            u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
        }
    };
    if read_u32(20) != 1 {
        return Err("unsupported ELF header version".into());
    }
    let header_size = read_u16(if elf_class == 32 { 40 } else { 52 });
    if usize::from(header_size) < minimum_size || u64::from(header_size) > total_bytes as u64 {
        return Err("invalid ELF header size".into());
    }
    Ok(FixedHeader {
        elf_class,
        byte_order_little: little_endian,
        header_size,
    })
}

/// Decode the supported ELF header and validate its table extents.
pub fn read_elf_header(bytes: &[u8], total_bytes: usize) -> Result<ElfHeader, String> {
    let reader = BoundedReader::new(bytes);
    let fixed = read_elf_fixed_header(bytes, total_bytes)?;
    let is64 = fixed.elf_class == 64;
    let header_bytes: usize = if is64 { ELF_HEADER_MAX_BYTES } else { 52 };
    if !fixed.byte_order_little {
        return Err("unsupported ELF byte order".into());
    }
    if usize::from(fixed.header_size) != header_bytes {
        return Err("unsupported ELF header size".into());
    }
    let e_type = reader.u16(0x10);
    if e_type != Some(1) && e_type != Some(2) && e_type != Some(ET_DYN) {
        return Err("unsupported ELF type".into());
    }
    let e_type = e_type.unwrap_or(0);

    let e_shoff = if is64 {
        reader.u64(0x28)
    } else {
        reader.u32(0x20).map(u64::from)
    };
    let e_shentsize = reader.u16(if is64 { 0x3a } else { 0x2e });
    let e_shnum = reader.u16(if is64 { 0x3c } else { 0x30 });
    let e_phoff = if is64 {
        reader.u64(0x20)
    } else {
        reader.u32(0x1c).map(u64::from)
    };
    let e_phentsize = reader.u16(if is64 { 0x36 } else { 0x2a });
    let e_phnum = reader.u16(if is64 { 0x38 } else { 0x2c });

    let total = total_bytes as u64;
    let header_bytes_u64 = header_bytes as u64;
    let table_fits = |offset: Option<u64>,
                      width: Option<usize>,
                      count: Option<usize>,
                      minimum_width: usize|
     -> bool {
        match (offset, width, count) {
            (Some(offset), Some(width), Some(count)) => {
                offset >= header_bytes_u64
                    && offset <= total
                    && width >= minimum_width
                    && count > 0
                    && (count as u64) <= (total - offset) / (width as u64)
            }
            _ => false,
        }
    };

    let min_shent: usize = if is64 { 64 } else { 40 };
    let dynamic_fallback = e_type == ET_DYN && e_shoff == Some(0) && e_shnum == Some(0);
    if e_shoff.is_none()
        || e_shentsize.is_none()
        || e_shnum.is_none()
        || (!dynamic_fallback
            && !table_fits(
                e_shoff,
                opt_u16_usize(e_shentsize),
                opt_u16_usize(e_shnum),
                min_shent,
            ))
    {
        return Err("ELF section header table is missing or out of bounds".into());
    }

    let min_phent: usize = if is64 { 56 } else { 32 };
    if e_phoff.is_none()
        || e_phentsize.is_none()
        || e_phnum.is_none()
        || e_phnum == Some(0xffff)
        || !table_fits(
            e_phoff,
            opt_u16_usize(e_phentsize),
            opt_u16_usize(e_phnum),
            min_phent,
        )
    {
        return Err("ELF program header table is missing or out of bounds".into());
    }

    Ok(ElfHeader {
        is64,
        dynamic_fallback,
        e_shoff: e_shoff.unwrap(),
        e_shentsize: e_shentsize.unwrap(),
        e_shnum: e_shnum.unwrap(),
        e_phoff: e_phoff.unwrap(),
        e_phentsize: e_phentsize.unwrap(),
        e_phnum: e_phnum.unwrap(),
    })
}

/// True when a valid supported ELF header is present
/// (`readElfHeader(...).header !== undefined`).
pub fn elf_header_valid(bytes: &[u8], total_bytes: usize) -> bool {
    read_elf_header(bytes, total_bytes).is_ok()
}

#[derive(Clone)]
pub struct ElfSymbol {
    pub name: String,
    /// File offset mapped from the virtual address through PT_LOAD.
    pub offset: usize,
    pub size: usize,
}

pub struct ElfSymbolInventory {
    pub symbols: Vec<ElfSymbol>,
    pub failures: Vec<String>,
}

struct LoadSegment {
    vaddr: u64,
    offset: u64,
    filesz: u64,
}

struct Span {
    start: u64,
    end: u64,
    delta: Option<i128>,
}

/// Port of `createElfLoadMap`: resolves `(address, size)` to a file offset.
struct LoadMap {
    spans: Vec<Span>,
    conflicts: Vec<u64>,
}

enum MapError {
    Missing,
    Ambiguous,
}

impl MapError {
    fn reason(&self) -> &'static str {
        match self {
            MapError::Missing => "has no contiguous file-backed PT_LOAD range",
            MapError::Ambiguous => "has conflicting PT_LOAD mappings",
        }
    }
}

impl LoadMap {
    fn new(segments: &[LoadSegment]) -> Self {
        struct Event {
            at: u64,
            delta: i128,
            change: i64,
        }
        let mut events: Vec<Event> = Vec::new();
        for segment in segments.iter().filter(|segment| segment.filesz > 0) {
            let delta = segment.offset as i128 - segment.vaddr as i128;
            events.push(Event {
                at: segment.vaddr,
                delta,
                change: 1,
            });
            events.push(Event {
                at: segment.vaddr + segment.filesz,
                delta,
                change: -1,
            });
        }
        events.sort_by(|left, right| left.at.cmp(&right.at));

        let mut active: HashMap<i128, i64> = HashMap::new();
        let mut spans: Vec<Span> = Vec::new();
        let mut previous = 0u64;
        for event in &events {
            if event.at > previous && !active.is_empty() {
                let delta = if active.len() == 1 {
                    active.keys().next().copied()
                } else {
                    None
                };
                match spans.last_mut() {
                    Some(last) if last.end == previous && last.delta == delta => {
                        last.end = event.at;
                    }
                    _ => spans.push(Span {
                        start: previous,
                        end: event.at,
                        delta,
                    }),
                }
            }
            let count = active.get(&event.delta).copied().unwrap_or(0) + event.change;
            if count == 0 {
                active.remove(&event.delta);
            } else {
                active.insert(event.delta, count);
            }
            previous = event.at;
        }

        let mut conflicts = vec![0u64];
        for span in &spans {
            let last = *conflicts.last().unwrap();
            conflicts.push(last + u64::from(span.delta.is_none()));
        }

        Self { spans, conflicts }
    }

    fn locate(&self, address: u64) -> isize {
        let mut low = 0isize;
        let mut high = self.spans.len() as isize;
        while low < high {
            let middle = (low + high) / 2;
            if self.spans[middle as usize].start <= address {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low - 1
    }

    fn resolve(&self, address: u64, size: u64) -> Result<usize, MapError> {
        if !is_safe_integer(address)
            || !is_safe_integer(size)
            || address.checked_add(size).map(is_safe_integer) != Some(true)
        {
            return Err(MapError::Missing);
        }
        let first = self.locate(address);
        if first < 0 {
            return Err(MapError::Missing);
        }
        let span = &self.spans[first as usize];
        if size > 0 && address >= span.end {
            return Err(MapError::Missing);
        }
        if size == 0 {
            if address > span.end {
                return Err(MapError::Missing);
            }
            let left = if first > 0 {
                self.spans.get((first - 1) as usize)
            } else {
                None
            };
            let left_conflict = span.delta.is_none()
                || (span.start == address
                    && left.map(|left| left.end) == Some(address)
                    && left.map(|left| left.delta) != Some(span.delta));
            if left_conflict {
                return Err(MapError::Ambiguous);
            }
            let delta = span.delta.unwrap();
            return Ok((address as i128 + delta) as usize);
        }
        let last = self.locate(address + size - 1);
        if last < 0 {
            return Err(MapError::Missing);
        }
        if self.conflicts[(last + 1) as usize] != self.conflicts[first as usize] {
            return Err(MapError::Ambiguous);
        }
        match span.delta {
            Some(delta) if address < span.end && size <= span.end - address => {
                Ok((address as i128 + delta) as usize)
            }
            _ => Err(MapError::Missing),
        }
    }
}

/// Decode the ELF tables once and resolve only the requested definitions.
pub fn read_elf_symbols(bytes: &[u8], symbol_names: &[&str]) -> ElfSymbolInventory {
    let failure = |reason: String| ElfSymbolInventory {
        symbols: Vec::new(),
        failures: vec![reason],
    };

    let header = match read_elf_header(bytes, bytes.len()) {
        Ok(header) => header,
        Err(reason) => return failure(reason),
    };
    let is64 = header.is64;
    let reader = BoundedReader::new(bytes);
    let entry_size: usize = if is64 { 24 } else { 16 };
    let total = bytes.len() as u64;

    let mut segments: Vec<LoadSegment> = Vec::new();
    let mut dynamic_segment: Option<(u64, u64)> = None;
    for index in 0..u64::from(header.e_phnum) {
        let base = (header.e_phoff + index * u64::from(header.e_phentsize)) as usize;
        let ptype = reader.u32(base);
        if ptype != Some(PT_LOAD) && ptype != Some(PT_DYNAMIC) {
            continue;
        }
        let vaddr = if is64 {
            reader.u64(base + 0x10)
        } else {
            reader.u32(base + 8).map(u64::from)
        };
        let offset = if is64 {
            reader.u64(base + 8)
        } else {
            reader.u32(base + 4).map(u64::from)
        };
        let filesz = if is64 {
            reader.u64(base + 0x20)
        } else {
            reader.u32(base + 0x10).map(u64::from)
        };
        let (vaddr, offset, filesz) = match (vaddr, offset, filesz) {
            (Some(vaddr), Some(offset), Some(filesz))
                if vaddr.checked_add(filesz).map(is_safe_integer) == Some(true)
                    && offset <= total
                    && filesz <= total - offset =>
            {
                (vaddr, offset, filesz)
            }
            _ => return failure(format!("ELF segment {index} is not file-backed")),
        };
        if ptype == Some(PT_LOAD) {
            segments.push(LoadSegment {
                vaddr,
                offset,
                filesz,
            });
        } else if dynamic_segment.is_some() {
            return failure("Multiple PT_DYNAMIC segments are ambiguous".into());
        } else {
            dynamic_segment = Some((offset, filesz));
        }
    }

    let load_map = LoadMap::new(&segments);
    if segments.is_empty() {
        return failure("ELF image has no PT_LOAD segments".into());
    }

    struct Table {
        offset: usize,
        count: usize,
        string_offset: usize,
        string_size: usize,
    }
    let mut tables: Vec<Table> = Vec::new();

    let section_mapping_failure =
        |header_offset: usize, offset: u64, size: u64| -> Option<String> {
            let flags = if is64 {
                reader.u64(header_offset + 8)
            } else {
                reader.u32(header_offset + 8).map(u64::from)
            };
            let address = if is64 {
                reader.u64(header_offset + 0x10)
            } else {
                reader.u32(header_offset + 0x0c).map(u64::from)
            };
            let (flags, address) = match (flags, address) {
                (Some(flags), Some(address)) => (flags, address),
                _ => return Some("has an unrepresentable section header".into()),
            };
            if (flags & SHF_ALLOC) == 0 {
                return None;
            }
            match load_map.resolve(address, size) {
                Ok(mapped) => {
                    if mapped as u64 == offset {
                        None
                    } else {
                        Some("section offset disagrees with its PT_LOAD mapping".into())
                    }
                }
                Err(error) => Some(error.reason().into()),
            }
        };

    if !header.dynamic_fallback {
        for index in 0..u64::from(header.e_shnum) {
            let section_header = (header.e_shoff + index * u64::from(header.e_shentsize)) as usize;
            if reader.u32(section_header + 4) != Some(SHT_DYNSYM) {
                continue;
            }
            let offset = if is64 {
                reader.u64(section_header + 0x18)
            } else {
                reader.u32(section_header + 0x10).map(u64::from)
            };
            let size = if is64 {
                reader.u64(section_header + 0x20)
            } else {
                reader.u32(section_header + 0x14).map(u64::from)
            };
            let width = if is64 {
                reader.u64(section_header + 0x38)
            } else {
                reader.u32(section_header + 0x24).map(u64::from)
            };
            let link = reader.u32(section_header + if is64 { 0x28 } else { 0x18 });
            let (offset, size) = match (offset, size) {
                (Some(offset), Some(size))
                    if width == Some(entry_size as u64)
                        && offset <= total
                        && size <= total - offset
                        && size % (entry_size as u64) == 0 =>
                {
                    (offset, size)
                }
                _ => return failure("Dynamic symbol table is malformed".into()),
            };
            let link = match link {
                Some(link) if (link as u64) < u64::from(header.e_shnum) => link,
                _ => return failure("Dynamic symbol string section link is invalid".into()),
            };
            let string_header =
                (header.e_shoff + u64::from(link) * u64::from(header.e_shentsize)) as usize;
            let string_offset = if is64 {
                reader.u64(string_header + 0x18)
            } else {
                reader.u32(string_header + 0x10).map(u64::from)
            };
            let string_size = if is64 {
                reader.u64(string_header + 0x20)
            } else {
                reader.u32(string_header + 0x14).map(u64::from)
            };
            let (string_offset, string_size) = match (string_offset, string_size) {
                (Some(string_offset), Some(string_size))
                    if reader.u32(string_header + 4) == Some(3)
                        && string_offset <= total
                        && string_size <= total - string_offset =>
                {
                    (string_offset, string_size)
                }
                _ => {
                    return failure(
                        "Dynamic symbol strings are out of bounds or not a string table".into(),
                    );
                }
            };
            if let Some(reason) = section_mapping_failure(section_header, offset, size) {
                return failure(format!("Dynamic symbol table {reason}"));
            }
            if let Some(reason) = section_mapping_failure(string_header, string_offset, string_size)
            {
                return failure(format!("Dynamic symbol string table {reason}"));
            }
            tables.push(Table {
                offset: offset as usize,
                count: (size / entry_size as u64) as usize,
                string_offset: string_offset as usize,
                string_size: string_size as usize,
            });
        }
    } else if let Some((dyn_offset, dyn_filesz)) = dynamic_segment {
        let mut tags: HashMap<u64, u64> = HashMap::new();
        let dynamic_entry_size: u64 = if is64 { 16 } else { 8 };
        let mut terminated = false;
        let mut base = dyn_offset;
        while base + dynamic_entry_size <= dyn_offset + dyn_filesz {
            let tag = if is64 {
                reader.u64(base as usize)
            } else {
                reader.u32(base as usize).map(u64::from)
            };
            let value = if is64 {
                reader.u64((base + 8) as usize)
            } else {
                reader.u32((base + 4) as usize).map(u64::from)
            };
            let (tag, value) = match (tag, value) {
                (Some(tag), Some(value)) => (tag, value),
                _ => return failure("Dynamic entry is not representable".into()),
            };
            if tag == DT_NULL {
                terminated = true;
                break;
            }
            if ![DT_SYMTAB, DT_STRTAB, DT_STRSZ, DT_SYMENT, 4, 0x6fff_fef5].contains(&tag) {
                base += dynamic_entry_size;
                continue;
            }
            if tags.get(&tag).is_some_and(|existing| *existing != value) {
                return failure("Conflicting dynamic table tags".into());
            }
            tags.insert(tag, value);
            base += dynamic_entry_size;
        }
        let sym = tags.get(&DT_SYMTAB).copied();
        let str_tab = tags.get(&DT_STRTAB).copied();
        let string_size = tags.get(&DT_STRSZ).copied();
        if !terminated
            || sym.is_none()
            || str_tab.is_none()
            || string_size.is_none()
            || tags.get(&DT_SYMENT) != Some(&(entry_size as u64))
        {
            return failure(
                "Stripped ELF lacks a complete dynamic symbol-table description".into(),
            );
        }
        let sym = sym.unwrap();
        let str_tab = str_tab.unwrap();
        let string_size = string_size.unwrap();

        let count: u64;
        let sysv = tags.get(&4).copied();
        let gnu = tags.get(&0x6fff_fef5).copied();
        if let Some(sysv) = sysv {
            let at = match load_map.resolve(sysv, 8) {
                Ok(at) => at,
                Err(error) => return failure(format!("DT_HASH header {}", error.reason())),
            };
            let buckets = reader.u32(at).unwrap_or(0);
            count = reader.u32(at + 4).unwrap_or(0) as u64;
            let table_span = 8 + 4 * (u64::from(buckets) + count);
            if let Err(error) = load_map.resolve(sysv, table_span) {
                return failure(format!("DT_HASH table {}", error.reason()));
            }
        } else if let Some(gnu) = gnu {
            let at = match load_map.resolve(gnu, 16) {
                Ok(at) => at,
                Err(error) => return failure(format!("DT_GNU_HASH header {}", error.reason())),
            };
            let buckets = reader.u32(at).unwrap_or(0);
            let first_symbol = reader.u32(at + 4).unwrap_or(0);
            let bloom_words = reader.u32(at + 8).unwrap_or(0);
            let bloom_entry: u64 = if is64 { 8 } else { 4 };
            let prefix_bytes = 16 + u64::from(bloom_words) * bloom_entry + u64::from(buckets) * 4;
            if buckets == 0 || bloom_words == 0 {
                return failure("DT_GNU_HASH buckets are malformed".into());
            }
            if let Err(error) = load_map.resolve(gnu, prefix_bytes) {
                return failure(format!("DT_GNU_HASH buckets {}", error.reason()));
            }
            let mut last: u32 = 0;
            let buckets_at = at + 16 + (bloom_words as usize) * (bloom_entry as usize);
            for index in 0..buckets {
                let value = reader.u32(buckets_at + (index as usize) * 4).unwrap_or(0);
                if value != 0 && value < first_symbol {
                    return failure("DT_GNU_HASH bucket precedes its first symbol".into());
                }
                last = last.max(value);
            }
            let mut resolved = u64::from(first_symbol);
            if last != 0 {
                let mut index = last;
                loop {
                    let span = prefix_bytes + u64::from(index - first_symbol + 1) * 4;
                    if let Err(error) = load_map.resolve(gnu, span) {
                        return failure(format!("DT_GNU_HASH chain {}", error.reason()));
                    }
                    let chain = reader.u32(at + span as usize - 4).unwrap_or(0);
                    index += 1;
                    if (chain & 1) != 0 {
                        resolved = u64::from(index);
                        break;
                    }
                }
            }
            count = resolved;
        } else {
            return failure("Stripped ELF has no DT_HASH or DT_GNU_HASH symbol count".into());
        }

        let offset = load_map.resolve(sym, count * entry_size as u64);
        let string_offset = load_map.resolve(str_tab, string_size);
        let offset = match offset {
            Ok(offset) => offset,
            Err(error) => return failure(format!("Dynamic symbol table {}", error.reason())),
        };
        let string_offset = match string_offset {
            Ok(string_offset) => string_offset,
            Err(error) => return failure(format!("Dynamic string table {}", error.reason())),
        };
        tables.push(Table {
            offset,
            count: count as usize,
            string_offset,
            string_size: string_size as usize,
        });
    }

    let wanted: HashSet<&str> = symbol_names.iter().copied().collect();
    let mut symbols: HashMap<String, ElfSymbol> = HashMap::new();
    // Preserve first-insertion order, matching the JavaScript `Map`.
    let mut order: Vec<String> = Vec::new();
    let mut ambiguous: HashSet<String> = HashSet::new();
    let mut unresolved: HashSet<String> = HashSet::new();
    let mut failures: Vec<String> = Vec::new();
    let mut failure_set: HashSet<String> = HashSet::new();
    let add_failure =
        |failures: &mut Vec<String>, failure_set: &mut HashSet<String>, reason: String| {
            if failure_set.insert(reason.clone()) {
                failures.push(reason);
            }
        };

    for table in &tables {
        for index in 0..table.count {
            let base = table.offset + index * entry_size;
            let name_offset = reader.u32(base).unwrap_or(0);
            let section_index = reader.u16(base + if is64 { 6 } else { 14 }).unwrap_or(0);
            let defined = section_index == 0xfff1
                || (section_index > 0
                    && section_index < 0xff00
                    && (header.dynamic_fallback
                        || (section_index as u64) < u64::from(header.e_shnum)));
            if !defined || (name_offset as usize) >= table.string_size {
                continue;
            }
            let name = match reader.c_string(
                table.string_offset + name_offset as usize,
                table.string_offset + table.string_size,
            ) {
                Some(name) => name,
                None => continue,
            };
            if !wanted.contains(name.as_str()) {
                continue;
            }
            let value = if is64 {
                reader.u64(base + 8)
            } else {
                reader.u32(base + 4).map(u64::from)
            };
            let size = if is64 {
                reader.u64(base + 16)
            } else {
                reader.u32(base + 8).map(u64::from)
            };
            let (value, size) = match (value, size) {
                (Some(value), Some(size)) => (value, size),
                _ => {
                    add_failure(
                        &mut failures,
                        &mut failure_set,
                        format!("Symbol {name} has unrepresentable bounds"),
                    );
                    unresolved.insert(name);
                    continue;
                }
            };
            let offset = match load_map.resolve(value, size) {
                Ok(offset) => offset,
                Err(error) => {
                    add_failure(
                        &mut failures,
                        &mut failure_set,
                        format!("Symbol {name} {}", error.reason()),
                    );
                    unresolved.insert(name);
                    continue;
                }
            };
            match symbols.get(&name) {
                Some(previous) if previous.offset != offset || previous.size != size as usize => {
                    ambiguous.insert(name);
                }
                _ => {
                    if !symbols.contains_key(&name) {
                        order.push(name.clone());
                    }
                    symbols.insert(
                        name.clone(),
                        ElfSymbol {
                            name,
                            offset,
                            size: size as usize,
                        },
                    );
                }
            }
        }
    }

    for name in &ambiguous {
        symbols.remove(name);
        add_failure(
            &mut failures,
            &mut failure_set,
            format!("Symbol {name} has conflicting definitions"),
        );
    }
    for name in &unresolved {
        symbols.remove(name);
    }
    for &name in symbol_names {
        if !symbols.contains_key(name) && !ambiguous.contains(name) && !unresolved.contains(name) {
            add_failure(
                &mut failures,
                &mut failure_set,
                format!("symbol {name} is not in the dynamic symbol table"),
            );
        }
    }

    let symbols: Vec<ElfSymbol> = order
        .into_iter()
        .filter_map(|name| symbols.get(&name).cloned())
        .collect();

    ElfSymbolInventory { symbols, failures }
}

/// One decoded Dart snapshot section header.
pub struct SnapshotHeader {
    pub magic_valid: bool,
    pub kind: Option<u64>,
    pub header_length: Option<u64>,
    pub hash: Option<String>,
    pub complete: bool,
}

/// Read one Dart snapshot section header from its file offset.
pub fn read_snapshot_header(bytes: &[u8], offset: usize) -> SnapshotHeader {
    let reader = BoundedReader::new(bytes);
    let magic = reader.u32(offset);
    if magic != Some(0xdcdc_f5f5) {
        return SnapshotHeader {
            magic_valid: false,
            kind: None,
            header_length: None,
            hash: None,
            complete: false,
        };
    }
    let header_length = reader.u64(offset + 4);
    let kind = reader.u64(offset + 12);
    let hash = {
        let start = offset + SNAPSHOT_HASH_OFFSET;
        let end = start + SNAPSHOT_HASH_LENGTH;
        if end <= bytes.len() {
            let candidate: String = bytes[start..end].iter().map(|&byte| byte as char).collect();
            if is_snapshot_hash(&candidate) {
                Some(candidate)
            } else {
                None
            }
        } else {
            None
        }
    };
    let complete = header_length.is_some_and(|length| {
        length >= (SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH - 4) as u64
            && length <= (bytes.len() - offset - 4) as u64
    }) && kind == Some(3)
        && hash.is_some();
    SnapshotHeader {
        magic_valid: true,
        kind,
        header_length,
        hash,
        complete,
    }
}
