//! Static discovery of IL2CPP `Il2CppCodeGenModule` records.
//!
//! This is deliberately a candidate finder rather than a registration resolver.  A
//! stripped binary can contain several pointer-shaped regions and Unity has changed
//! the surrounding registration structures over time.  Every row that satisfies the
//! supplied byte and mapping evidence is retained; callers decide whether additional
//! evidence is sufficient to identify one row.
//!
//! The supported record is the common metadata 29/31/39 generated layout:
//! `moduleName`, method-pointer count/table, adjustor-thunk count/table,
//! invoker-indices table, reverse-P/Invoke count/table, RGCTX range count/table,
//! RGCTX count/table, debugger metadata, and module metadata registration.  Counts
//! are 32-bit values and pointers use the caller's declared width.  Padding follows
//! the native alignment of the pointer width.  This module does not open files,
//! parse ELF/PE/Mach-O headers, execute code, or infer a process address space.

use std::fmt;

const MAX_NAME_BYTES: usize = 4 * 1024;
const MAX_POINTER_COUNT: u64 = 16 * 1024 * 1024;
const MAX_CANDIDATES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerWidth {
    Bits32,
    Bits64,
}

impl PointerWidth {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endianness {
    Little,
    Big,
}

/// A caller-provided file-image mapping.  `virtual_start..virtual_end` and
/// `file_start..file_end` describe the same byte interval.  Overlapping mappings
/// are retained as ambiguous instead of being resolved by ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressMapping {
    pub virtual_start: u64,
    pub virtual_end: u64,
    pub file_start: u64,
    pub file_end: u64,
}

impl AddressMapping {
    pub const fn new(virtual_start: u64, virtual_end: u64, file_start: u64, file_end: u64) -> Self {
        Self {
            virtual_start,
            virtual_end,
            file_start,
            file_end,
        }
    }

    fn valid(self) -> bool {
        self.virtual_start < self.virtual_end
            && self.file_start < self.file_end
            && self.virtual_end - self.virtual_start == self.file_end - self.file_start
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveryInput<'a> {
    pub image: &'a [u8],
    pub pointer_width: PointerWidth,
    pub endianness: Endianness,
    pub mappings: &'a [AddressMapping],
    pub executable_ranges: &'a [AddressRange],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
    pub fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateDisposition {
    Valid,
    Ambiguous,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateIssue {
    pub field: &'static str,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeGenModuleCandidate {
    pub record_file_offset: usize,
    pub record_byte_length: usize,
    pub record_virtual_address: Option<u64>,
    pub module_name: Option<String>,
    pub module_name_file_offset: Option<usize>,
    pub module_name_virtual_address: Option<u64>,
    pub method_pointer_count: Option<u32>,
    pub method_pointer_table: Option<u64>,
    pub method_pointer_table_file_offset: Option<usize>,
    pub method_pointer_table_byte_length: Option<usize>,
    pub method_pointers: Vec<MethodPointerObservation>,
    pub disposition: CandidateDisposition,
    pub issues: Vec<CandidateIssue>,
}

/// Stable ownership facts for a discovered module.
///
/// A record offset alone is only meaningful inside one captured image.  The
/// module name and the method-table address provide the two source-owned facts
/// that downstream layout and decompilation joins can carry across projections.
/// The count and captured table extent distinguish otherwise similar records
/// while retaining the record's unique virtual identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeGenModuleOwnership {
    pub module_name: String,
    pub record_virtual_address: u64,
    pub method_pointer_table: u64,
    pub method_pointer_count: u32,
    pub method_pointer_table_file_offset: Option<usize>,
    pub method_pointer_table_byte_length: Option<usize>,
    pub validated_method_pointer_table: Option<ValidatedMethodPointerTable>,
}

/// A method-pointer table extent whose slots were all mapped to executable
/// ranges during discovery.  A zero-count module has no executable extent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMethodPointerTable {
    pub virtual_address: u64,
    pub file_offset: usize,
    pub byte_length: usize,
    pub pointer_count: u32,
}

impl CodeGenModuleCandidate {
    /// Return ownership facts only when this row is structurally unique.
    ///
    /// Rejected and ambiguous rows deliberately remain unavailable here.  A
    /// caller may still retain their complete candidate and issues, but must
    /// not use unresolved facts as a join key for a later workflow.
    pub fn ownership(&self) -> Option<CodeGenModuleOwnership> {
        if self.disposition != CandidateDisposition::Valid {
            return None;
        }

        let module_name = self.module_name.clone()?;
        let record_virtual_address = self.record_virtual_address?;
        let method_pointer_table = self.method_pointer_table?;
        let method_pointer_count = self.method_pointer_count?;

        Some(CodeGenModuleOwnership {
            module_name,
            record_virtual_address,
            method_pointer_table,
            method_pointer_count,
            method_pointer_table_file_offset: self.method_pointer_table_file_offset,
            method_pointer_table_byte_length: self.method_pointer_table_byte_length,
            validated_method_pointer_table: self.validated_method_pointer_table(),
        })
    }

    /// Associate this module with its executable method-pointer table only
    /// after every slot has been validated.  The candidate itself remains
    /// available when the association is unresolved or competing.
    pub fn validated_method_pointer_table(&self) -> Option<ValidatedMethodPointerTable> {
        if self.disposition != CandidateDisposition::Valid {
            return None;
        }

        let pointer_count = self.method_pointer_count?;
        let virtual_address = self.method_pointer_table?;
        let file_offset = self.method_pointer_table_file_offset?;
        let byte_length = self.method_pointer_table_byte_length?;

        if pointer_count == 0
            || self.method_pointers.len() != pointer_count as usize
            || self
                .method_pointers
                .iter()
                .any(|pointer| pointer.disposition != MethodPointerDisposition::Valid)
        {
            return None;
        }

        Some(ValidatedMethodPointerTable {
            virtual_address,
            file_offset,
            byte_length,
            pointer_count,
        })
    }

    /// Produce the deterministic identity used by downstream joins.
    pub fn ownership_key(&self) -> Option<String> {
        let ownership = self.ownership()?;

        Some(format!(
            "{}@0x{:x}/0x{:x}#{}:file={:?}:bytes={:?}",
            ownership.module_name,
            ownership.record_virtual_address,
            ownership.method_pointer_table,
            ownership.method_pointer_count,
            ownership.method_pointer_table_file_offset,
            ownership.method_pointer_table_byte_length,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodPointerObservation {
    pub index: usize,
    pub target_virtual_address: Option<u64>,
    pub target_file_offset: Option<usize>,
    pub mapping_count: usize,
    pub executable_range_matches: Vec<AddressRange>,
    pub disposition: MethodPointerDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodPointerDisposition {
    Valid,
    Null,
    Unmapped,
    AmbiguousMapping,
    OutsideImage,
    NonExecutable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryReport {
    pub candidates: Vec<CodeGenModuleCandidate>,
    pub scanned_offsets: usize,
    pub truncated: bool,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    InvalidMapping { index: usize },
    InvalidExecutableRange { index: usize },
    EmptyImage,
    UnsupportedPointerWidth,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMapping { index } => write!(f, "mapping {index} has inconsistent ranges"),
            Self::InvalidExecutableRange { index } => {
                write!(f, "executable range {index} has inconsistent bounds")
            }
            Self::EmptyImage => f.write_str("the supplied image is empty"),
            Self::UnsupportedPointerWidth => f.write_str("pointer width must be 32 or 64 bits"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Discover all plausible records in a supplied static image.
///
/// The scan is bounded by the image length and [`MAX_CANDIDATES`].  Candidate
/// records are emitted even when a field is unresolved; an unresolved mapping,
/// malformed string, or non-executable method target is recorded as an issue.
/// A row is `Valid` only when all required evidence is unique and valid, and is
/// `Ambiguous` whenever mapping overlap or an unresolved pointer prevents that
/// conclusion.
pub fn discover(input: DiscoveryInput<'_>) -> Result<DiscoveryReport, DiscoveryError> {
    if input.image.is_empty() {
        return Err(DiscoveryError::EmptyImage);
    }
    if input.pointer_width.bytes() != 4 && input.pointer_width.bytes() != 8 {
        return Err(DiscoveryError::UnsupportedPointerWidth);
    }
    for (index, mapping) in input.mappings.iter().copied().enumerate() {
        if !mapping.valid() {
            return Err(DiscoveryError::InvalidMapping { index });
        }
    }
    for (index, range) in input.executable_ranges.iter().copied().enumerate() {
        if range.start >= range.end {
            return Err(DiscoveryError::InvalidExecutableRange { index });
        }
    }

    let width = input.pointer_width.bytes();
    let alignment = width;
    let record_size = record_size(width);
    let mut candidates = Vec::new();
    let mut scanned_offsets = 0;
    let mut offset = 0usize;
    while offset
        .checked_add(record_size)
        .is_some_and(|end| end <= input.image.len())
    {
        scanned_offsets += 1;
        if let Some(candidate) = inspect_record(&input, offset) {
            if candidates.len() == MAX_CANDIDATES {
                return Ok(DiscoveryReport {
                    candidates,
                    scanned_offsets,
                    truncated: true,
                    limitations: limitations(),
                });
            }
            candidates.push(candidate);
        }
        offset = offset.saturating_add(alignment);
    }

    Ok(DiscoveryReport {
        candidates,
        scanned_offsets,
        truncated: false,
        limitations: limitations(),
    })
}

fn record_size(width: usize) -> usize {
    // Fourteen fields: eight pointers and six uint32 counts.  Native alignment
    // inserts padding before each pointer following a count on 64-bit images.
    let mut cursor = 0usize;
    cursor += width; // module name
    cursor = align(cursor, width);
    cursor += 4; // method count
    cursor = align(cursor, width);
    cursor += width; // method table
    cursor = align(cursor, width);
    cursor += 4; // adjustor count
    cursor = align(cursor, width);
    cursor += width; // adjustor table
    cursor = align(cursor, width);
    cursor += width; // invoker indices
    cursor = align(cursor, width);
    cursor += 4; // reverse P/Invoke count
    cursor = align(cursor, width);
    cursor += width; // reverse P/Invoke table
    cursor = align(cursor, width);
    cursor += 4; // RGCTX range count
    cursor = align(cursor, width);
    cursor += width; // RGCTX ranges
    cursor = align(cursor, width);
    cursor += 4; // RGCTX count
    cursor = align(cursor, width);
    cursor += width; // RGCTX data
    cursor = align(cursor, width);
    cursor += width; // debugger metadata
    cursor = align(cursor, width);
    cursor += width; // module metadata
    align(cursor, width)
}

fn inspect_record(
    input: &DiscoveryInput<'_>,
    record_offset: usize,
) -> Option<CodeGenModuleCandidate> {
    let width = input.pointer_width.bytes();
    let module_name = read_pointer(input.image, record_offset, width, input.endianness)?;
    if module_name == 0 {
        return None;
    }

    let mut issues = Vec::new();
    let record_virtual_address = unique_virtual_for_file(input, record_offset);
    let record_end = record_offset.saturating_add(record_size(input.pointer_width.bytes()));
    let record_mapping_count = mappings_for_file_span(input, record_offset, record_end).len();
    if record_mapping_count == 0 {
        issues.push(issue("record", "record has no supplied file mapping"));
    } else if record_mapping_count > 1 {
        issues.push(issue(
            "record",
            "record has multiple supplied file mappings or crosses a mapping boundary",
        ));
    }
    let name_location = resolve_unique(input, module_name);
    let (module_name_virtual_address, name) = match name_location {
        UniqueLocation::One {
            file_offset,
            virtual_address,
        } => match read_c_string(input.image, file_offset) {
            Ok(name)
                if !name.is_empty()
                    && file_offset.checked_add(name.len() + 1).is_some_and(|end| {
                        mappings_for_file_span(input, file_offset, end).len() == 1
                    }) =>
            {
                (Some(virtual_address), Some(name))
            }
            Ok(name) if !name.is_empty() => {
                issues.push(issue(
                    "module_name",
                    "module name crosses supplied file mappings",
                ));
                (Some(virtual_address), None)
            }
            Ok(_) => {
                issues.push(issue("module_name", "module name is empty"));
                (Some(virtual_address), None)
            }
            Err(reason) => {
                issues.push(issue("module_name", reason));
                (Some(virtual_address), None)
            }
        },
        UniqueLocation::None => {
            issues.push(issue("module_name", "pointer has no supplied file mapping"));
            (None, None)
        }
        UniqueLocation::Many => {
            issues.push(issue(
                "module_name",
                "pointer has multiple supplied file mappings",
            ));
            (None, None)
        }
    };

    let count_offset = align(record_offset + width, width);
    let method_pointer_count = read_u32(input.image, count_offset, input.endianness);
    let method_table_offset = align(count_offset + 4, width);
    let method_table = read_pointer(input.image, method_table_offset, width, input.endianness);
    let mut method_pointer_table_file_offset = None;
    let mut method_pointer_table_byte_length = None;
    let mut method_pointers = Vec::new();
    let (count, table) = match (method_pointer_count, method_table) {
        (Some(count), Some(table)) => {
            validate_method_table(
                input,
                count,
                table,
                &mut method_pointer_table_file_offset,
                &mut method_pointer_table_byte_length,
                &mut method_pointers,
                &mut issues,
            );
            (Some(count), Some(table))
        }
        _ => {
            issues.push(issue(
                "method_table",
                "method count or table pointer is truncated",
            ));
            (method_pointer_count, method_table)
        }
    };

    let all_method_pointers_valid = match (count, table) {
        (Some(0), Some(0)) => true,
        (Some(count), Some(table)) if table != 0 => {
            method_pointers.len() == count as usize
                && method_pointers
                    .iter()
                    .all(|pointer| pointer.disposition == MethodPointerDisposition::Valid)
        }
        _ => false,
    };
    let disposition = if issues.iter().any(|item| item.reason.contains("multiple")) {
        CandidateDisposition::Ambiguous
    } else if issues
        .iter()
        .any(|item| item.reason.contains("no supplied") || item.reason.contains("unresolved"))
    {
        CandidateDisposition::Ambiguous
    } else if issues.is_empty() && record_virtual_address.is_some() && all_method_pointers_valid {
        CandidateDisposition::Valid
    } else {
        CandidateDisposition::Rejected
    };

    Some(CodeGenModuleCandidate {
        record_file_offset: record_offset,
        record_byte_length: record_size(width),
        record_virtual_address,
        module_name: name,
        module_name_file_offset: match name_location {
            UniqueLocation::One { file_offset, .. } => Some(file_offset),
            UniqueLocation::None | UniqueLocation::Many => None,
        },
        module_name_virtual_address,
        method_pointer_count: count,
        method_pointer_table: table,
        method_pointer_table_file_offset,
        method_pointer_table_byte_length,
        method_pointers,
        disposition,
        issues,
    })
}

fn validate_method_table(
    input: &DiscoveryInput<'_>,
    count: u32,
    table: u64,
    table_file_offset: &mut Option<usize>,
    table_byte_length: &mut Option<usize>,
    observations: &mut Vec<MethodPointerObservation>,
    issues: &mut Vec<CandidateIssue>,
) {
    if u64::from(count) > MAX_POINTER_COUNT {
        issues.push(issue(
            "method_pointer_count",
            "count exceeds the static safety bound",
        ));
        return;
    }
    if count == 0 {
        if table != 0 {
            issues.push(issue(
                "method_pointer_table",
                "zero method count has a non-null table",
            ));
        }
        return;
    }
    if table == 0 {
        issues.push(issue(
            "method_pointer_table",
            "non-zero method count has a null table",
        ));
        return;
    }
    let bytes = match usize::try_from(
        u64::from(count).saturating_mul(input.pointer_width.bytes() as u64),
    ) {
        Ok(bytes) => bytes,
        Err(_) => {
            issues.push(issue(
                "method_pointer_table",
                "table size overflows host usize",
            ));
            return;
        }
    };
    let location = resolve_unique(input, table);
    let file_offset = match location {
        UniqueLocation::One { file_offset, .. } => file_offset,
        UniqueLocation::None => {
            issues.push(issue(
                "method_pointer_table",
                "table pointer has no supplied file mapping",
            ));
            return;
        }
        UniqueLocation::Many => {
            issues.push(issue(
                "method_pointer_table",
                "table pointer has multiple supplied file mappings",
            ));
            return;
        }
    };
    *table_file_offset = Some(file_offset);
    *table_byte_length = Some(bytes);
    if file_offset
        .checked_add(bytes)
        .is_none_or(|end| end > input.image.len())
    {
        issues.push(issue(
            "method_pointer_table",
            "table range is outside the supplied image",
        ));
        observations.push(MethodPointerObservation {
            index: 0,
            target_virtual_address: None,
            target_file_offset: None,
            mapping_count: 1,
            executable_range_matches: Vec::new(),
            disposition: MethodPointerDisposition::OutsideImage,
        });
        return;
    }
    for index in 0..count as usize {
        let Some(target) = read_pointer(
            input.image,
            file_offset + index * input.pointer_width.bytes(),
            input.pointer_width.bytes(),
            input.endianness,
        ) else {
            issues.push(issue("method_pointer_table", "method target is truncated"));
            observations.push(MethodPointerObservation {
                index,
                target_virtual_address: None,
                target_file_offset: None,
                mapping_count: 0,
                executable_range_matches: Vec::new(),
                disposition: MethodPointerDisposition::OutsideImage,
            });
            break;
        };
        if target == 0 {
            issues.push(issue("method_pointer_table", "method target is null"));
            observations.push(MethodPointerObservation {
                index,
                target_virtual_address: Some(target),
                target_file_offset: None,
                mapping_count: 0,
                executable_range_matches: Vec::new(),
                disposition: MethodPointerDisposition::Null,
            });
            continue;
        }
        let mappings = matching_mappings(input, target);
        let executable_range_matches = input
            .executable_ranges
            .iter()
            .copied()
            .filter(|range| range.contains(target))
            .collect::<Vec<_>>();
        let target_file_offset = (mappings.len() == 1).then_some(mappings[0]);
        let disposition = if mappings.is_empty() {
            issues.push(issue(
                "method_pointer_table",
                "method target has no supplied file mapping",
            ));
            MethodPointerDisposition::Unmapped
        } else if mappings.len() > 1 {
            issues.push(issue(
                "method_pointer_table",
                "method target has multiple supplied file mappings",
            ));
            MethodPointerDisposition::AmbiguousMapping
        } else if target_file_offset.is_some_and(|offset| offset >= input.image.len()) {
            issues.push(issue(
                "method_pointer_table",
                "method target maps outside the supplied image",
            ));
            MethodPointerDisposition::OutsideImage
        } else if executable_range_matches.is_empty() {
            issues.push(issue(
                "method_pointer_table",
                "method target is outside supplied executable ranges",
            ));
            MethodPointerDisposition::NonExecutable
        } else if executable_range_matches.len() > 1 {
            issues.push(issue(
                "method_pointer_table",
                "method target has multiple supplied executable ranges",
            ));
            MethodPointerDisposition::AmbiguousMapping
        } else {
            MethodPointerDisposition::Valid
        };
        observations.push(MethodPointerObservation {
            index,
            target_virtual_address: Some(target),
            target_file_offset,
            mapping_count: mappings.len(),
            executable_range_matches,
            disposition,
        });
    }
}

#[derive(Clone, Copy)]
enum UniqueLocation {
    None,
    One {
        file_offset: usize,
        virtual_address: u64,
    },
    Many,
}

fn resolve_unique(input: &DiscoveryInput<'_>, address: u64) -> UniqueLocation {
    let mut result = None;
    let mut match_count = 0usize;
    for mapping in input
        .mappings
        .iter()
        .copied()
        .filter(|mapping| mapping.virtual_start <= address && address < mapping.virtual_end)
    {
        let Some(file) = mapping
            .file_start
            .checked_add(address - mapping.virtual_start)
            .and_then(|v| usize::try_from(v).ok())
        else {
            continue;
        };
        match_count += 1;
        if match_count > 1 {
            return UniqueLocation::Many;
        }
        result = Some((file, address));
    }
    match result {
        Some((file_offset, virtual_address)) => UniqueLocation::One {
            file_offset,
            virtual_address,
        },
        None => UniqueLocation::None,
    }
}

fn matching_mappings(input: &DiscoveryInput<'_>, address: u64) -> Vec<usize> {
    input
        .mappings
        .iter()
        .copied()
        .filter(|mapping| mapping.virtual_start <= address && address < mapping.virtual_end)
        .filter_map(|mapping| {
            mapping
                .file_start
                .checked_add(address - mapping.virtual_start)
                .and_then(|offset| usize::try_from(offset).ok())
        })
        .collect()
}

fn mappings_for_file_span(
    input: &DiscoveryInput<'_>,
    file_start: usize,
    file_end: usize,
) -> Vec<u64> {
    let (Ok(file_start), Ok(file_end)) = (u64::try_from(file_start), u64::try_from(file_end))
    else {
        return Vec::new();
    };

    input
        .mappings
        .iter()
        .copied()
        .filter(|mapping| mapping.file_start <= file_start && file_end <= mapping.file_end)
        .filter_map(|mapping| {
            mapping
                .virtual_start
                .checked_add(file_start - mapping.file_start)
        })
        .collect()
}

fn unique_virtual_for_file(input: &DiscoveryInput<'_>, file_offset: usize) -> Option<u64> {
    let mut result = None;
    for mapping in input.mappings.iter().copied() {
        let Ok(offset) = u64::try_from(file_offset) else {
            return None;
        };
        if mapping.file_start <= offset && offset < mapping.file_end {
            let Some(address) = mapping
                .virtual_start
                .checked_add(offset - mapping.file_start)
            else {
                return None;
            };
            if result.is_some() && result != Some(address) {
                return None;
            }
            result = Some(address);
        }
    }
    result
}

fn read_c_string(image: &[u8], offset: usize) -> Result<String, &'static str> {
    let end = image.len().min(offset.saturating_add(MAX_NAME_BYTES));
    let bytes = image
        .get(offset..end)
        .ok_or("module name is outside supplied image")?;
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("module name is not NUL terminated within the bound")?;
    let value = &bytes[..nul];
    if !value
        .iter()
        .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
    {
        return Err("module name contains non-printable bytes");
    }
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| "module name is not UTF-8")
}

fn read_pointer(image: &[u8], offset: usize, width: usize, endian: Endianness) -> Option<u64> {
    match width {
        4 => read_u32(image, offset, endian).map(u64::from),
        8 => image
            .get(offset..offset.checked_add(8)?)
            .map(|bytes| match endian {
                Endianness::Little => u64::from_le_bytes(bytes.try_into().unwrap()),
                Endianness::Big => u64::from_be_bytes(bytes.try_into().unwrap()),
            }),
        _ => None,
    }
}

fn read_u32(image: &[u8], offset: usize, endian: Endianness) -> Option<u32> {
    let bytes = image.get(offset..offset.checked_add(4)?)?;
    Some(match endian {
        Endianness::Little => u32::from_le_bytes(bytes.try_into().unwrap()),
        Endianness::Big => u32::from_be_bytes(bytes.try_into().unwrap()),
    })
}

fn align(value: usize, alignment: usize) -> usize {
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + alignment - remainder
    }
}

fn issue(field: &'static str, reason: &'static str) -> CandidateIssue {
    CandidateIssue {
        field,
        reason: reason.into(),
    }
}

fn limitations() -> Vec<String> {
    vec![
        "Discovery is static and uses only caller-supplied bytes, mappings, and executable ranges.".into(),
        "The common metadata 29/31/39 CodeGenModule field layout is supported; Unity forks or alternate packing remain unknown.".into(),
        "A valid candidate is structural evidence, not proof that the row is the active metadata registration.".into(),
    ]
}
