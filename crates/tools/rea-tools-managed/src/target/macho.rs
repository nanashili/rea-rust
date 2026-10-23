//! Mach-O thin and FAT (universal) header parsing, FAT identity classification,
//! and the JVM class-file disambiguation shared with the container reader.
//!
//! Ports `src/domain/binaryTarget.ts` (`parseThinMachO`, `parseFatMachO`,
//! `fatHostArchitecture`, `fatIdentityError`, `machArchitecture`) and
//! `src/domain/apple/machoContainer.ts` and `src/domain/apple/jvmClassFile.ts`.

use super::header::{ExecutableExtra, ExecutableMetadata, read_u32, read_u32_be};

const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_MAGIC_64: u32 = 0xcafebabf;
const FAT_CIGAM: u32 = 0xbebafeca;
const FAT_CIGAM_64: u32 = 0xbfbafeca;
const MAX_FAT_ARCHITECTURES: u32 = 128;

const KNOWN_MACHO_CPU_TYPES: &[u32] = &[7, 0x01000007, 12, 0x0100000c, 0x0200000c, 18, 0x01000012];
const MACHO_HEADER_MAGICS: &[u32] = &[0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe];

/// TS `machArchitecture(cpu)`.
fn mach_architecture(cpu: u32) -> Option<&'static str> {
    match cpu {
        7 => Some("x86"),
        0x01000007 => Some("x86_64"),
        12 => Some("arm"),
        0x0100000c => Some("arm64"),
        _ => None,
    }
}

/// TS `parseThinMachO(bytes, magic, fileSize)`.
pub(crate) fn parse_thin_macho(
    bytes: &[u8],
    magic: u32,
    file_size: u64,
) -> Result<ExecutableMetadata, String> {
    let is64 = magic == 0xfeedfacf || magic == 0xcffaedfe;
    let header_size: usize = if is64 { 32 } else { 28 };
    if bytes.len() < header_size {
        return Err(format!(
            "truncated Mach-O header: a {}-bit header needs {header_size} bytes; the file has {file_size}",
            if is64 { 64 } else { 32 }
        ));
    }
    let little = magic == 0xcefaedfe || magic == 0xcffaedfe;
    let read = |offset: usize| read_u32(bytes, offset, little);
    let architecture = match mach_architecture(read(4)) {
        Some(architecture) => architecture,
        None => return Err("unsupported Mach-O architecture".to_string()),
    };
    let command_bytes = read(20) as u64;
    if header_size as u64 + command_bytes > file_size {
        return Err(format!(
            "truncated Mach-O load commands: the header declares {command_bytes} bytes after its {header_size}-byte header; the file has {file_size}"
        ));
    }
    Ok(ExecutableMetadata {
        format: "mach-o",
        architecture: architecture.to_string(),
        available_architectures: vec![architecture.to_string()],
        extra: ExecutableExtra::None,
    })
}

/// Dispatch non-ELF / non-MZ / non-thin-Mach-O prefixes: FAT or unsupported.
///
/// TS `parseExecutableHeader`'s tail: read the FAT container header, and when
/// it is "not-fat", report "unsupported binary format".
pub(crate) fn parse_fat_or_unsupported(
    bytes: &[u8],
    host: &str,
    file_size: u64,
) -> Result<ExecutableMetadata, String> {
    match read_fat_container_header(bytes, file_size) {
        FatContainerHeader::NotFat => Err("unsupported binary format".to_string()),
        header => parse_fat_macho(bytes, host, header),
    }
}

/// TS `fatHostArchitecture(host)`.
fn fat_host_architecture(host: &str) -> Option<&'static str> {
    match host {
        "arm64" => Some("arm64"),
        "x64" => Some("x86_64"),
        "ia32" => Some("x86"),
        "arm" => Some("arm"),
        _ => None,
    }
}

/// TS `parseFatMachO(bytes, host, header)`.
fn parse_fat_macho(
    bytes: &[u8],
    host: &str,
    header: FatContainerHeader,
) -> Result<ExecutableMetadata, String> {
    let parsed = match header {
        FatContainerHeader::NeedsData { .. } => {
            return Err("truncated or invalid FAT architecture table".to_string());
        }
        FatContainerHeader::Malformed { reason } => return Err(reason),
        FatContainerHeader::NotFat => {
            // Unreachable from the dispatch, but matches TS exhaustiveness.
            return Err("unsupported binary format".to_string());
        }
        FatContainerHeader::Parsed(parsed) => parsed,
    };

    if let Some(error) = fat_identity_error(bytes, &parsed) {
        return Err(error);
    }

    let mut architectures: Vec<String> = Vec::new();
    let mut slices: Vec<(String, u64, u64)> = Vec::new();
    for declaration in &parsed.slices {
        let architecture = match mach_architecture(declaration.cpu_type) {
            Some(architecture) => architecture,
            None => continue,
        };
        if architectures
            .iter()
            .any(|existing| existing == architecture)
        {
            continue;
        }
        architectures.push(architecture.to_string());
        slices.push((
            architecture.to_string(),
            declaration.offset,
            declaration.size,
        ));
    }

    let preferred = fat_host_architecture(host);
    let slice = preferred.and_then(|preferred| {
        slices
            .iter()
            .find(|(architecture, _, _)| architecture == preferred)
            .map(|(_, offset, size)| (*offset, *size))
    });
    let (preferred, (offset, size)) = match (preferred, slice) {
        (Some(preferred), Some(slice)) => (preferred, slice),
        _ => {
            return Err(format!(
                "FAT binary has no host-compatible {host} architecture"
            ));
        }
    };

    let minimum_header_size: u64 = if preferred == "arm64" || preferred == "x86_64" {
        32
    } else {
        28
    };
    if size < minimum_header_size {
        return Err(format!(
            "FAT slice for {preferred} is shorter than its Mach-O header"
        ));
    }

    Ok(ExecutableMetadata {
        format: "mach-o-universal",
        architecture: preferred.to_string(),
        available_architectures: architectures,
        extra: ExecutableExtra::UniversalSlice { offset, size },
    })
}

/// One entry in a Mach-O FAT architecture table.
#[derive(Clone, Copy, Debug)]
struct FatSliceDeclaration {
    index: u32,
    offset: u64,
    size: u64,
    alignment_exponent: u32,
    cpu_type: u32,
}

#[derive(Clone, Copy, Debug)]
struct FatSliceRangeIssue {
    #[allow(dead_code)]
    category: RangeCategory,
    reason_kind: RangeReasonKind,
    index: u32,
    alignment_exponent: u32,
}

#[derive(Clone, Copy, Debug)]
enum RangeCategory {
    Malformed,
    Unsupported,
}

#[derive(Clone, Copy, Debug)]
enum RangeReasonKind {
    InvalidRange,
    ExtendsBeyond,
    UnsupportedAlignment,
    Misaligned,
}

impl FatSliceRangeIssue {
    fn reason(&self) -> String {
        match self.reason_kind {
            RangeReasonKind::InvalidRange => {
                format!("FAT architecture {} has an invalid slice range", self.index)
            }
            RangeReasonKind::ExtendsBeyond => {
                format!(
                    "FAT architecture {} slice range extends beyond the file",
                    self.index
                )
            }
            RangeReasonKind::UnsupportedAlignment => format!(
                "FAT architecture {} alignment exponent {} is unsupported",
                self.index, self.alignment_exponent
            ),
            RangeReasonKind::Misaligned => format!(
                "FAT architecture {} offset is not aligned to 2^{}",
                self.index, self.alignment_exponent
            ),
        }
    }
}

struct FatParsed {
    slices: Vec<FatSliceDeclaration>,
    range_issues: Vec<Option<FatSliceRangeIssue>>,
}

enum FatContainerHeader {
    NotFat,
    NeedsData {
        #[allow(dead_code)]
        required_bytes: u64,
    },
    Malformed {
        reason: String,
    },
    Parsed(FatParsed),
}

/// TS `readFatContainerHeader(bytes, fileSize)`.
fn read_fat_container_header(bytes: &[u8], file_size: u64) -> FatContainerHeader {
    if bytes.len() < 4 {
        return FatContainerHeader::NotFat;
    }
    let magic = read_u32_be(bytes, 0);
    if !matches!(magic, FAT_MAGIC | FAT_MAGIC_64 | FAT_CIGAM | FAT_CIGAM_64) {
        return FatContainerHeader::NotFat;
    }
    if file_size < bytes.len() as u64 {
        return FatContainerHeader::Malformed {
            reason: "FAT file size is invalid or contradicts retained bytes".to_string(),
        };
    }
    if bytes.len() as u64 == file_size && is_jvm_class_file(bytes) {
        return FatContainerHeader::NotFat;
    }
    if bytes.len() < 8 {
        return if file_size < 8 {
            FatContainerHeader::Malformed {
                reason: "FAT header is truncated".to_string(),
            }
        } else {
            FatContainerHeader::NeedsData { required_bytes: 8 }
        };
    }
    let little = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
    let wide = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    let count = read_u32(bytes, 4, little);
    if count == 0 {
        return FatContainerHeader::Malformed {
            reason: "FAT header declares no architectures".to_string(),
        };
    }
    if count > MAX_FAT_ARCHITECTURES {
        return FatContainerHeader::NotFat;
    }
    let entry_size: u64 = if wide { 32 } else { 20 };
    let table_end = 8 + count as u64 * entry_size;
    if table_end > file_size {
        return FatContainerHeader::NotFat;
    }
    if table_end > bytes.len() as u64 {
        return FatContainerHeader::NeedsData {
            required_bytes: table_end,
        };
    }
    let slices =
        match read_fat_slice_declarations(&bytes[8..table_end as usize], count, wide, little) {
            Ok(slices) => slices,
            Err(reason) => return FatContainerHeader::Malformed { reason },
        };
    let range_issues = slices
        .iter()
        .map(|slice| inspect_fat_slice_range(slice, file_size, table_end))
        .collect();
    FatContainerHeader::Parsed(FatParsed {
        slices,
        range_issues,
    })
}

fn read_fat_slice_declarations(
    table_bytes: &[u8],
    count: u32,
    wide: bool,
    little: bool,
) -> Result<Vec<FatSliceDeclaration>, String> {
    let entry_size: usize = if wide { 32 } else { 20 };
    if table_bytes.len() < count as usize * entry_size {
        return Err("FAT table is truncated".to_string());
    }
    let mut slices = Vec::with_capacity(count as usize);
    for index in 0..count {
        let base = index as usize * entry_size;
        let offset = if wide {
            match safe_number(read_u64(table_bytes, base + 8, little)) {
                Some(value) => value,
                None => return Err("FAT offset or size exceeds the safe range".to_string()),
            }
        } else {
            read_u32(table_bytes, base + 8, little) as u64
        };
        let size = if wide {
            match safe_number(read_u64(table_bytes, base + 16, little)) {
                Some(value) => value,
                None => return Err("FAT offset or size exceeds the safe range".to_string()),
            }
        } else {
            read_u32(table_bytes, base + 12, little) as u64
        };
        let alignment_exponent = read_u32(table_bytes, base + if wide { 24 } else { 16 }, little);
        let cpu_type = read_u32(table_bytes, base, little);
        slices.push(FatSliceDeclaration {
            index,
            offset,
            size,
            alignment_exponent,
            cpu_type,
        });
    }
    Ok(slices)
}

/// TS `inspectFatSliceRange`.
fn inspect_fat_slice_range(
    declaration: &FatSliceDeclaration,
    container_size: u64,
    table_end: u64,
) -> Option<FatSliceRangeIssue> {
    let FatSliceDeclaration {
        index,
        offset,
        size,
        alignment_exponent,
        ..
    } = *declaration;
    if size == 0 || offset < table_end {
        return Some(FatSliceRangeIssue {
            category: RangeCategory::Malformed,
            reason_kind: RangeReasonKind::InvalidRange,
            index,
            alignment_exponent,
        });
    }
    if offset > container_size || size > container_size - offset {
        return Some(FatSliceRangeIssue {
            category: RangeCategory::Malformed,
            reason_kind: RangeReasonKind::ExtendsBeyond,
            index,
            alignment_exponent,
        });
    }
    if alignment_exponent > 52 {
        return Some(FatSliceRangeIssue {
            category: RangeCategory::Unsupported,
            reason_kind: RangeReasonKind::UnsupportedAlignment,
            index,
            alignment_exponent,
        });
    }
    // offset % 2^alignmentExponent !== 0
    if alignment_exponent < 64 && offset % (1u64 << alignment_exponent) != 0 {
        return Some(FatSliceRangeIssue {
            category: RangeCategory::Malformed,
            reason_kind: RangeReasonKind::Misaligned,
            index,
            alignment_exponent,
        });
    }
    None
}

/// TS `fatIdentityError(bytes, header)`.
fn fat_identity_error(bytes: &[u8], parsed: &FatParsed) -> Option<String> {
    match classify_fat_container_identity(parsed, |offset| {
        let offset = offset as usize;
        if offset >= bytes.len() {
            return SliceHeader::Undefined;
        }
        if offset + 4 > bytes.len() {
            return SliceHeader::Null;
        }
        SliceHeader::Magic(read_u32_be(bytes, offset))
    }) {
        FatContainerIdentity::NeedsSliceHeader => {
            Some("FAT slice identity is outside the bounded prefix".to_string())
        }
        FatContainerIdentity::NotMachO => {
            Some("FAT table does not identify a Mach-O image".to_string())
        }
        FatContainerIdentity::Malformed { reason } => Some(reason),
        FatContainerIdentity::MachO => None,
    }
}

enum SliceHeader {
    Undefined,
    Null,
    Magic(u32),
}

enum FatContainerIdentity {
    MachO,
    NotMachO,
    NeedsSliceHeader,
    Malformed { reason: String },
}

/// TS `classifyFatContainerIdentity(header, sliceHeaderAt)`.
fn classify_fat_container_identity(
    parsed: &FatParsed,
    slice_header_at: impl Fn(u64) -> SliceHeader,
) -> FatContainerIdentity {
    let has_known_cpu = parsed
        .slices
        .iter()
        .any(|slice| KNOWN_MACHO_CPU_TYPES.contains(&slice.cpu_type));
    let invalid_range = parsed.range_issues.iter().find_map(|issue| issue.as_ref());

    if has_known_cpu {
        return match invalid_range {
            None => FatContainerIdentity::MachO,
            Some(issue) => FatContainerIdentity::Malformed {
                reason: issue.reason(),
            },
        };
    }

    let mut missing_headers = false;
    let mut observed_macho = false;
    for (index, slice) in parsed.slices.iter().enumerate() {
        if parsed.range_issues[index].is_some() {
            continue; // only valid ranges
        }
        match slice_header_at(slice.offset) {
            SliceHeader::Undefined => missing_headers = true,
            SliceHeader::Null => {}
            SliceHeader::Magic(magic) => {
                if MACHO_HEADER_MAGICS.contains(&magic) {
                    observed_macho = true;
                }
            }
        }
    }

    if observed_macho {
        return match invalid_range {
            None => FatContainerIdentity::MachO,
            Some(issue) => FatContainerIdentity::Malformed {
                reason: issue.reason(),
            },
        };
    }
    if missing_headers {
        return FatContainerIdentity::NeedsSliceHeader;
    }
    FatContainerIdentity::NotMachO
}

fn read_u64(bytes: &[u8], offset: usize, little: bool) -> u64 {
    if offset + 8 > bytes.len() {
        return 0;
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    }
}

/// TS `safeNumber`: reject values beyond Number.MAX_SAFE_INTEGER (2^53 - 1).
fn safe_number(value: u64) -> Option<u64> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    if value > MAX_SAFE_INTEGER {
        None
    } else {
        Some(value)
    }
}

// ----- jvmClassFile.ts -----

/// TS `isJvmClassFile(bytes)`.
pub(crate) fn is_jvm_class_file(bytes: &[u8]) -> bool {
    let mut cursor = ClassFileCursor::new(bytes);
    if cursor.u4() != Some(0xcafebabe) {
        return false;
    }
    let minor = cursor.u2();
    let major = cursor.u2();
    let pool_count = cursor.u2();
    let (Some(_minor), Some(major), Some(pool_count)) = (minor, major, pool_count) else {
        return false;
    };
    if major < 45 || pool_count == 0 {
        return false;
    }
    let pool = match read_constant_pool(&mut cursor, pool_count) {
        Some(pool) => pool,
        None => return false,
    };
    if !has_valid_pool_references(&pool, major) {
        return false;
    }
    if cursor.u2().is_none() {
        return false;
    }
    let this_class = cursor.u2();
    let super_class = cursor.u2();
    let (Some(this_class), Some(super_class)) = (this_class, super_class) else {
        return false;
    };
    if !pool_has_tag(&pool, this_class as usize, &[7]) {
        return false;
    }
    if super_class != 0 && !pool_has_tag(&pool, super_class as usize, &[7]) {
        return false;
    }
    let interfaces = match cursor.u2() {
        Some(interfaces) => interfaces,
        None => return false,
    };
    if !cursor.skip(interfaces as i64 * 2) {
        return false;
    }
    if !read_members(&mut cursor, &pool) || !read_members(&mut cursor, &pool) {
        return false;
    }
    let attributes = match cursor.u2() {
        Some(attributes) => attributes,
        None => return false,
    };
    read_attributes(&mut cursor, &pool, attributes) && cursor.at_end()
}

struct ClassFileCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ClassFileCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn has(&self, length: usize) -> bool {
        self.offset <= self.bytes.len().saturating_sub(length) && self.bytes.len() >= length
    }
    fn u1(&mut self) -> Option<u32> {
        if !self.has(1) {
            return None;
        }
        let value = self.bytes[self.offset] as u32;
        self.offset += 1;
        Some(value)
    }
    fn u2(&mut self) -> Option<u32> {
        if !self.has(2) {
            return None;
        }
        let value = read_u16_be_cursor(self.bytes, self.offset) as u32;
        self.offset += 2;
        Some(value)
    }
    fn u4(&mut self) -> Option<u32> {
        if !self.has(4) {
            return None;
        }
        let value = read_u32_be(self.bytes, self.offset);
        self.offset += 4;
        Some(value)
    }
    fn skip(&mut self, length: i64) -> bool {
        if length < 0 {
            return false;
        }
        let length = length as usize;
        if !self.has(length) {
            return false;
        }
        self.offset += length;
        true
    }
}

fn read_u16_be_cursor(bytes: &[u8], offset: usize) -> u16 {
    read_u16_le(bytes, offset).swap_bytes() // placeholder, replaced below
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    super::header::read_u16_le(bytes, offset)
}

struct ConstantPool {
    tags: Vec<Option<u32>>,
    first: Vec<Option<u32>>,
    second: Vec<Option<u32>>,
}

fn read_constant_pool(cursor: &mut ClassFileCursor, count: u32) -> Option<ConstantPool> {
    let count = count as usize;
    let mut pool = ConstantPool {
        tags: vec![None; count],
        first: vec![None; count],
        second: vec![None; count],
    };
    let mut index = 1usize;
    while index < count {
        let tag = cursor.u1()?;
        if !read_constant(cursor, tag, index, &mut pool) {
            return None;
        }
        if tag == 5 || tag == 6 {
            index += 1;
        }
        index += 1;
    }
    Some(pool)
}

fn read_constant(
    cursor: &mut ClassFileCursor,
    tag: u32,
    index: usize,
    pool: &mut ConstantPool,
) -> bool {
    match tag {
        1 => {
            let Some(length) = cursor.u2() else {
                return false;
            };
            if !cursor.skip(length as i64) {
                return false;
            }
        }
        3 | 4 => {
            if cursor.u4().is_none() {
                return false;
            }
        }
        5 | 6 => {
            if index + 1 >= pool.tags.len() || !cursor.skip(8) {
                return false;
            }
        }
        7 | 8 | 16 | 19 | 20 => {
            pool.first[index] = cursor.u2();
            if pool.first[index].is_none() {
                return false;
            }
        }
        9 | 10 | 11 | 12 | 17 | 18 => {
            pool.first[index] = cursor.u2();
            pool.second[index] = cursor.u2();
            if pool.first[index].is_none() || pool.second[index].is_none() {
                return false;
            }
        }
        15 => {
            pool.first[index] = cursor.u1();
            pool.second[index] = cursor.u2();
            if pool.first[index].is_none() || pool.second[index].is_none() {
                return false;
            }
        }
        _ => return false,
    }
    pool.tags[index] = Some(tag);
    true
}

fn pool_has_tag(pool: &ConstantPool, index: usize, tags: &[u32]) -> bool {
    index > 0 && index < pool.tags.len() && tags.contains(&pool.tags[index].unwrap_or(u32::MAX))
}

fn has_valid_pool_references(pool: &ConstantPool, major: u32) -> bool {
    for index in 1..pool.tags.len() {
        let tag = pool.tags[index];
        let first = pool.first[index];
        let second = pool.second[index];
        let tag_value = tag.unwrap_or(u32::MAX);
        if [7, 8, 16, 19, 20].contains(&tag_value) {
            match first {
                Some(first) if pool_has_tag(pool, first as usize, &[1]) => {}
                _ => return false,
            }
            if (tag_value == 16 && major < 51)
                || ((tag_value == 19 || tag_value == 20) && major < 53)
            {
                return false;
            }
        } else if [9, 10, 11].contains(&tag_value) {
            match (first, second) {
                (Some(first), Some(second))
                    if pool_has_tag(pool, first as usize, &[7])
                        && pool_has_tag(pool, second as usize, &[12]) => {}
                _ => return false,
            }
        } else if tag_value == 12 {
            match (first, second) {
                (Some(first), Some(second))
                    if pool_has_tag(pool, first as usize, &[1])
                        && pool_has_tag(pool, second as usize, &[1]) => {}
                _ => return false,
            }
        } else if tag_value == 15 {
            if !valid_method_handle(pool, first, second, major) {
                return false;
            }
        } else if tag_value == 17 || tag_value == 18 {
            match second {
                Some(second) if pool_has_tag(pool, second as usize, &[12]) => {}
                _ => return false,
            }
            if major < if tag_value == 17 { 55 } else { 51 } {
                return false;
            }
        }
    }
    true
}

fn valid_method_handle(
    pool: &ConstantPool,
    kind: Option<u32>,
    reference: Option<u32>,
    major: u32,
) -> bool {
    let (Some(kind), Some(reference)) = (kind, reference) else {
        return false;
    };
    if kind < 1 || kind > 9 || major < 51 {
        return false;
    }
    let reference = reference as usize;
    if kind <= 4 {
        return pool_has_tag(pool, reference, &[9]);
    }
    if kind == 5 || kind == 8 {
        return pool_has_tag(pool, reference, &[10]);
    }
    if kind == 6 || kind == 7 {
        return if major >= 52 {
            pool_has_tag(pool, reference, &[10, 11])
        } else {
            pool_has_tag(pool, reference, &[10])
        };
    }
    pool_has_tag(pool, reference, &[11])
}

fn read_attributes(cursor: &mut ClassFileCursor, pool: &ConstantPool, count: u32) -> bool {
    for _ in 0..count {
        let name = cursor.u2();
        let length = cursor.u4();
        let (Some(name), Some(length)) = (name, length) else {
            return false;
        };
        if !pool_has_tag(pool, name as usize, &[1]) || !cursor.skip(length as i64) {
            return false;
        }
    }
    true
}

fn read_members(cursor: &mut ClassFileCursor, pool: &ConstantPool) -> bool {
    let count = match cursor.u2() {
        Some(count) => count,
        None => return false,
    };
    for _ in 0..count {
        if cursor.u2().is_none() {
            return false;
        }
        let name = cursor.u2();
        let descriptor = cursor.u2();
        let attributes = cursor.u2();
        let (Some(name), Some(descriptor), Some(attributes)) = (name, descriptor, attributes)
        else {
            return false;
        };
        if !pool_has_tag(pool, name as usize, &[1])
            || !pool_has_tag(pool, descriptor as usize, &[1])
            || !read_attributes(cursor, pool, attributes)
        {
            return false;
        }
    }
    true
}
