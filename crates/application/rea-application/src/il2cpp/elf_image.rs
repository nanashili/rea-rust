//! Checked, read-only address mapping for caller-supplied ELF images.
//!
//! This module intentionally does not load an image or consult process state.  It
//! models only the ELF program headers present in the supplied bytes, which is
//! sufficient for locating IL2CPP data in a file image while keeping unresolved
//! mappings explicit.

use std::fmt;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const MAX_PROGRAM_HEADERS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfEndianness {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfMachine(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    pub fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    /// Original index in the ELF program-header table.
    pub program_header_index: usize,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
    pub alignment: u64,
}

impl LoadSegment {
    pub fn file_range(&self) -> Option<AddressRange> {
        range(self.file_offset, self.file_size)
    }

    pub fn memory_range(&self) -> Option<AddressRange> {
        range(self.virtual_address, self.memory_size)
    }

    /// The virtual range backed by bytes in the supplied file image.
    pub fn file_backed_memory_range(&self) -> Option<AddressRange> {
        range(self.virtual_address, self.file_size)
    }

    pub fn executable_range(&self) -> Option<AddressRange> {
        (self.flags & PF_X != 0)
            .then(|| self.memory_range())
            .flatten()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMapping {
    pub virtual_address: u64,
    pub file_offset: u64,
    pub segment: LoadSegment,
}

/// One normalized virtual mapping from the supplied ELF image.
///
/// A load segment may have a zero-fill tail after its file-backed bytes. The
/// tail remains part of the virtual mapping while `file_range` stays absent,
/// so callers cannot accidentally read it from the input image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageMapping {
    pub segment: usize,
    pub virtual_range: AddressRange,
    pub file_range: Option<AddressRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingResolution {
    Unmapped,
    VirtualOnly,
    FileBacked(FileMapping),
    Ambiguous { candidate_count: usize },
}

/// Resolution of an address used as a native method pointer.
///
/// The file mapping is retained for executable and non-executable results so
/// callers can report the original PT_LOAD evidence alongside the decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableAddressResolution {
    Unmapped,
    VirtualOnly,
    FileBackedNonExecutable(FileMapping),
    FileBackedExecutable(FileMapping),
    Ambiguous { candidate_count: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooSmall,
    InvalidMagic,
    UnsupportedClass(u8),
    UnsupportedEndianness(u8),
    InvalidHeader(&'static str),
    OutOfBounds(&'static str),
    Overflow(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => formatter.write_str("ELF header is truncated"),
            Self::InvalidMagic => formatter.write_str("ELF magic is invalid"),
            Self::UnsupportedClass(value) => write!(formatter, "unsupported ELF class {value}"),
            Self::UnsupportedEndianness(value) => {
                write!(formatter, "unsupported ELF endianness {value}")
            }
            Self::InvalidHeader(reason) => write!(formatter, "invalid ELF header: {reason}"),
            Self::OutOfBounds(field) => write!(formatter, "ELF {field} exceeds the supplied bytes"),
            Self::Overflow(field) => write!(formatter, "ELF {field} overflows"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ElfImage {
    class: ElfClass,
    endianness: ElfEndianness,
    machine: ElfMachine,
    segments: Vec<LoadSegment>,
}

impl ElfImage {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (class, endianness, header_size) = parse_ident(bytes)?;
        if bytes.len() < header_size {
            return Err(Error::TooSmall);
        }

        validate_header(bytes, class, endianness, header_size)?;

        let file_type = read_u16(bytes, 16, endianness)?;
        if !matches!(file_type, ET_REL | ET_EXEC | ET_DYN) {
            return Err(Error::InvalidHeader("ELF file type is unsupported"));
        }

        let machine = ElfMachine(read_u16(bytes, 18, endianness)?);
        let (program_header_offset, entry_size, count) = match class {
            ElfClass::Elf32 => (
                u64::from(read_u32(bytes, 28, endianness)?),
                u64::from(read_u16(bytes, 42, endianness)?),
                usize::from(read_u16(bytes, 44, endianness)?),
            ),
            ElfClass::Elf64 => (
                read_u64(bytes, 32, endianness)?,
                u64::from(read_u16(bytes, 54, endianness)?),
                usize::from(read_u16(bytes, 56, endianness)?),
            ),
        };
        let expected_entry_size = match class {
            ElfClass::Elf32 => 32,
            ElfClass::Elf64 => 56,
        };
        if entry_size < expected_entry_size {
            return Err(Error::InvalidHeader(
                "program header entry size is too small",
            ));
        }
        if count > MAX_PROGRAM_HEADERS {
            return Err(Error::InvalidHeader("program header count is unreasonable"));
        }
        if count == usize::from(u16::MAX) {
            return Err(Error::InvalidHeader(
                "extended program header numbering is unsupported",
            ));
        }
        if count != 0 && program_header_offset < header_size as u64 {
            return Err(Error::InvalidHeader(
                "program header table overlaps the ELF header",
            ));
        }
        let header_end = checked_table_end(
            program_header_offset,
            entry_size,
            count,
            "program header table",
        )?;
        if header_end > bytes.len() as u64 {
            return Err(Error::OutOfBounds("program header table"));
        }

        let mut segments = Vec::new();
        for index in 0..count {
            let offset = program_header_offset
                .checked_add(
                    entry_size
                        .checked_mul(index as u64)
                        .ok_or(Error::Overflow("program header index"))?,
                )
                .ok_or(Error::Overflow("program header offset"))?;
            let at =
                usize::try_from(offset).map_err(|_| Error::Overflow("program header offset"))?;
            let segment = read_load_segment(bytes, at, index, class, endianness)?;
            if let Some(segment) = segment {
                validate_segment(segment, bytes.len() as u64, class)?;
                segments.push(segment);
            }
        }

        if segments.is_empty() {
            return Err(Error::InvalidHeader("ELF image has no PT_LOAD segments"));
        }

        Ok(Self {
            class,
            endianness,
            machine,
            segments,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(bytes)
    }

    pub fn class(&self) -> ElfClass {
        self.class
    }
    pub fn endianness(&self) -> ElfEndianness {
        self.endianness
    }
    pub fn machine(&self) -> ElfMachine {
        self.machine
    }
    pub fn load_segments(&self) -> &[LoadSegment] {
        &self.segments
    }

    pub fn virtual_address_to_file_offset(&self, address: u64) -> Option<u64> {
        unique_mapping(self.segments.iter().map(|segment| {
            let file_backed = segment.file_backed_memory_range()?;
            file_backed
                .contains(address)
                .then(|| {
                    segment
                        .file_offset
                        .checked_add(address - segment.virtual_address)
                })
                .flatten()
        }))
    }

    pub fn va_to_file_offset(&self, address: u64) -> Option<u64> {
        self.virtual_address_to_file_offset(address)
    }

    pub fn file_offset_to_virtual_address(&self, offset: u64) -> Option<u64> {
        unique_mapping(self.segments.iter().map(|segment| {
            let file = segment.file_range()?;
            file.contains(offset)
                .then(|| {
                    segment
                        .virtual_address
                        .checked_add(offset - segment.file_offset)
                })
                .flatten()
        }))
    }

    pub fn file_offset_to_va(&self, offset: u64) -> Option<u64> {
        self.file_offset_to_virtual_address(offset)
    }

    /// Return every virtual mapping, retaining zero-fill tails explicitly.
    pub fn mappings(&self) -> Vec<ImageMapping> {
        self.segments
            .iter()
            .enumerate()
            .filter_map(|(segment, value)| {
                let virtual_range = value.memory_range()?;
                let file_range = value.file_backed_memory_range();
                Some(ImageMapping {
                    segment,
                    virtual_range,
                    file_range,
                })
            })
            .collect()
    }

    /// Resolve a virtual address while distinguishing absent, virtual-only,
    /// file-backed, and overlapping mappings.
    pub fn resolve_virtual_address(&self, address: u64) -> MappingResolution {
        let mut file_backed_candidates = Vec::new();
        let mut has_virtual_only_candidate = false;
        for (segment_index, segment) in self.segments.iter().enumerate() {
            let Some(virtual_range) = segment.memory_range() else {
                continue;
            };
            if !virtual_range.contains(address) {
                continue;
            }

            let file_mapping = segment.file_backed_memory_range().and_then(|range| {
                if !range.contains(address) {
                    return None;
                }

                let file_offset = segment.file_offset.checked_add(address - range.start)?;
                Some(FileMapping {
                    virtual_address: address,
                    file_offset,
                    segment: *segment,
                })
            });
            if let Some(mapping) = file_mapping {
                file_backed_candidates.push((segment_index, mapping));
            } else {
                has_virtual_only_candidate = true;
            }
        }

        match file_backed_candidates.as_slice() {
            [] if has_virtual_only_candidate => MappingResolution::VirtualOnly,
            [] => MappingResolution::Unmapped,
            [(_, mapping)] => MappingResolution::FileBacked(*mapping),
            _ => MappingResolution::Ambiguous {
                candidate_count: file_backed_candidates.len(),
            },
        }
    }

    pub fn is_file_backed_address(&self, address: u64) -> bool {
        matches!(
            self.resolve_virtual_address(address),
            MappingResolution::FileBacked(_)
        )
    }

    /// Return the remaining virtual bytes in the unique load segment that
    /// contains an address. This includes a segment's zero-fill tail.
    pub fn virtual_bytes_remaining(&self, address: u64) -> u64 {
        let mut result = None;
        for segment in &self.segments {
            let Some(range) = segment.memory_range() else {
                continue;
            };
            if !range.contains(address) {
                continue;
            }
            if result.is_some() {
                return 0;
            }
            result = range.end.checked_sub(address);
        }
        result.unwrap_or(0)
    }

    /// Return the remaining source bytes in the unique file-backed mapping.
    /// Virtual-only tails therefore report zero.
    pub fn file_backed_bytes_remaining(&self, address: u64) -> u64 {
        match self.resolve_virtual_address(address) {
            MappingResolution::FileBacked(mapping) => mapping
                .segment
                .file_backed_memory_range()
                .and_then(|range| range.end.checked_sub(address))
                .unwrap_or(0),
            MappingResolution::Unmapped
            | MappingResolution::VirtualOnly
            | MappingResolution::Ambiguous { .. } => 0,
        }
    }

    pub fn is_executable_file_backed_address(&self, address: u64) -> bool {
        self.is_file_backed_address(address)
            && self
                .mapping_for_virtual_address(address)
                .is_some_and(|mapping| mapping.segment.flags & PF_X != 0)
    }

    /// Resolve a method-pointer address without treating zero-fill bytes as
    /// readable instructions. Overlapping PT_LOAD ranges remain ambiguous,
    /// even when one candidate is executable and another is not.
    pub fn resolve_executable_address(&self, address: u64) -> ExecutableAddressResolution {
        match self.resolve_virtual_address(address) {
            MappingResolution::Unmapped => ExecutableAddressResolution::Unmapped,
            MappingResolution::VirtualOnly => ExecutableAddressResolution::VirtualOnly,
            MappingResolution::FileBacked(mapping) => {
                if mapping.segment.flags & PF_X != 0 {
                    ExecutableAddressResolution::FileBackedExecutable(mapping)
                } else {
                    ExecutableAddressResolution::FileBackedNonExecutable(mapping)
                }
            }
            MappingResolution::Ambiguous { candidate_count } => {
                ExecutableAddressResolution::Ambiguous { candidate_count }
            }
        }
    }

    /// Return only executable bytes that are present in the supplied file.
    pub fn executable_file_backed_ranges(&self) -> Vec<AddressRange> {
        self.segments
            .iter()
            .filter(|segment| segment.flags & PF_X != 0)
            .filter_map(LoadSegment::file_backed_memory_range)
            .collect()
    }

    pub fn mapping_for_virtual_address(&self, address: u64) -> Option<FileMapping> {
        match self.resolve_virtual_address(address) {
            MappingResolution::FileBacked(mapping) => Some(mapping),
            MappingResolution::Unmapped
            | MappingResolution::VirtualOnly
            | MappingResolution::Ambiguous { .. } => None,
        }
    }

    /// Map a complete caller-requested byte range. A range crossing a segment
    /// boundary, a zero-fill tail, or an overlapping segment is unresolved.
    pub fn mapping_for_virtual_range(&self, address: u64, size: u64) -> Option<FileMapping> {
        if size == 0 {
            return None;
        }
        let end = address.checked_add(size)?;

        let mut mapping = None;
        for segment in &self.segments {
            let Some(file_backed_range) = segment.file_backed_memory_range() else {
                continue;
            };
            if !ranges_overlap(
                file_backed_range,
                AddressRange {
                    start: address,
                    end,
                },
            ) {
                continue;
            }

            // Any overlapping PT_LOAD interpretation makes the requested
            // range ambiguous, including a virtual-only overlap.
            if mapping.is_some() {
                return None;
            }

            if address < file_backed_range.start || end > file_backed_range.end {
                return None;
            }
            let file_offset = segment
                .file_offset
                .checked_add(address - file_backed_range.start)?;
            mapping = Some(FileMapping {
                virtual_address: address,
                file_offset,
                segment: *segment,
            });
        }

        mapping
    }

    pub fn executable_ranges(&self) -> Vec<AddressRange> {
        self.segments
            .iter()
            .filter_map(|segment| segment.executable_range())
            .collect()
    }

    pub fn executable_range_containing(&self, address: u64) -> Option<AddressRange> {
        let mut result = None;
        for range in self
            .executable_ranges()
            .into_iter()
            .filter(|range| range.contains(address))
        {
            // Duplicate or overlapping executable PT_LOAD ranges do not
            // establish a unique owning segment. Keep the result unknown
            // rather than selecting one range by header order.
            if result.is_some() {
                return None;
            }
            result = Some(range);
        }
        result
    }

    pub fn executable_file_backed_range_containing(&self, address: u64) -> Option<AddressRange> {
        unique_range(
            self.executable_file_backed_ranges()
                .into_iter()
                .filter(|range| range.contains(address)),
        )
    }

    pub fn executable_range(&self, address: u64) -> Option<AddressRange> {
        self.executable_range_containing(address)
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_range_containing(address).is_some()
    }
}

fn parse_ident(bytes: &[u8]) -> Result<(ElfClass, ElfEndianness, usize), Error> {
    if bytes.len() < 16 {
        return Err(Error::TooSmall);
    }
    if &bytes[..4] != ELF_MAGIC {
        return Err(Error::InvalidMagic);
    }
    let class = match bytes[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        value => return Err(Error::UnsupportedClass(value)),
    };
    let endianness = match bytes[5] {
        1 => ElfEndianness::Little,
        2 => ElfEndianness::Big,
        value => return Err(Error::UnsupportedEndianness(value)),
    };
    if bytes[6] != 1 {
        return Err(Error::InvalidHeader(
            "identification version is unsupported",
        ));
    }
    Ok((
        class,
        endianness,
        match class {
            ElfClass::Elf32 => 52,
            ElfClass::Elf64 => 64,
        },
    ))
}

fn validate_header(
    bytes: &[u8],
    class: ElfClass,
    endianness: ElfEndianness,
    minimum_size: usize,
) -> Result<(), Error> {
    if read_u32(bytes, 20, endianness)? != 1 {
        return Err(Error::InvalidHeader("header version is unsupported"));
    }

    let declared_size = match class {
        ElfClass::Elf32 => read_u16(bytes, 40, endianness)?,
        ElfClass::Elf64 => read_u16(bytes, 52, endianness)?,
    } as usize;
    if declared_size < minimum_size {
        return Err(Error::InvalidHeader("ELF header size is too small"));
    }
    if declared_size > bytes.len() {
        return Err(Error::OutOfBounds("ELF header"));
    }

    Ok(())
}

fn read_load_segment(
    bytes: &[u8],
    at: usize,
    program_header_index: usize,
    class: ElfClass,
    endianness: ElfEndianness,
) -> Result<Option<LoadSegment>, Error> {
    let kind = read_u32(bytes, at, endianness)?;
    if kind != PT_LOAD {
        return Ok(None);
    }
    let segment = match class {
        ElfClass::Elf32 => LoadSegment {
            program_header_index,
            virtual_address: u64::from(read_u32(bytes, at + 8, endianness)?),
            file_offset: u64::from(read_u32(bytes, at + 4, endianness)?),
            file_size: u64::from(read_u32(bytes, at + 16, endianness)?),
            memory_size: u64::from(read_u32(bytes, at + 20, endianness)?),
            flags: read_u32(bytes, at + 24, endianness)?,
            alignment: u64::from(read_u32(bytes, at + 28, endianness)?),
        },
        ElfClass::Elf64 => LoadSegment {
            program_header_index,
            virtual_address: read_u64(bytes, at + 16, endianness)?,
            file_offset: read_u64(bytes, at + 8, endianness)?,
            file_size: read_u64(bytes, at + 32, endianness)?,
            memory_size: read_u64(bytes, at + 40, endianness)?,
            flags: read_u32(bytes, at + 4, endianness)?,
            alignment: read_u64(bytes, at + 48, endianness)?,
        },
    };
    Ok(Some(segment))
}

fn validate_segment(segment: LoadSegment, length: u64, class: ElfClass) -> Result<(), Error> {
    if segment.file_size > segment.memory_size {
        return Err(Error::InvalidHeader(
            "segment file size exceeds memory size",
        ));
    }
    if segment.alignment > 1 {
        if !segment.alignment.is_power_of_two() {
            return Err(Error::InvalidHeader(
                "load segment alignment is not a power of two",
            ));
        }
        if segment.virtual_address % segment.alignment != segment.file_offset % segment.alignment {
            return Err(Error::InvalidHeader(
                "load segment address and file offset are misaligned",
            ));
        }
    }
    let file_end = segment
        .file_offset
        .checked_add(segment.file_size)
        .ok_or(Error::Overflow("segment file range"))?;
    if file_end > length {
        return Err(Error::OutOfBounds("load segment"));
    }
    let virtual_end = segment
        .virtual_address
        .checked_add(segment.memory_size)
        .ok_or(Error::Overflow("segment virtual range"))?;
    let address_limit = match class {
        ElfClass::Elf32 => 1_u64 << 32,
        ElfClass::Elf64 => u64::MAX,
    };
    if virtual_end > address_limit {
        return Err(Error::InvalidHeader(
            "segment virtual range exceeds ELF class",
        ));
    }
    Ok(())
}

fn checked_table_end(
    start: u64,
    entry_size: u64,
    count: usize,
    field: &'static str,
) -> Result<u64, Error> {
    start
        .checked_add(
            entry_size
                .checked_mul(count as u64)
                .ok_or(Error::Overflow(field))?,
        )
        .ok_or(Error::Overflow(field))
}

fn range(start: u64, size: u64) -> Option<AddressRange> {
    Some(AddressRange {
        start,
        end: start.checked_add(size)?,
    })
}

fn ranges_overlap(left: AddressRange, right: AddressRange) -> bool {
    left.start < right.end && right.start < left.end
}

fn unique_mapping(values: impl Iterator<Item = Option<u64>>) -> Option<u64> {
    let mut result = None;
    for value in values.flatten() {
        // A second matching PT_LOAD is ambiguous even if both headers yield
        // the same translated offset. The caller must retain the segment
        // identity when it needs to disambiguate the mapping.
        if result.is_some() {
            return None;
        }
        result = Some(value);
    }
    result
}

fn unique_range(values: impl Iterator<Item = AddressRange>) -> Option<AddressRange> {
    let mut result = None;
    for value in values {
        if result.is_some() {
            return None;
        }
        result = Some(value);
    }
    result
}

fn read_u16(bytes: &[u8], offset: usize, endianness: ElfEndianness) -> Result<u16, Error> {
    let data = bytes
        .get(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or(Error::Overflow("field offset"))?,
        )
        .ok_or(Error::OutOfBounds("header field"))?;
    Ok(match endianness {
        ElfEndianness::Little => u16::from_le_bytes([data[0], data[1]]),
        ElfEndianness::Big => u16::from_be_bytes([data[0], data[1]]),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endianness: ElfEndianness) -> Result<u32, Error> {
    let data = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or(Error::Overflow("field offset"))?,
        )
        .ok_or(Error::OutOfBounds("ELF field"))?;
    Ok(match endianness {
        ElfEndianness::Little => u32::from_le_bytes(data.try_into().unwrap()),
        ElfEndianness::Big => u32::from_be_bytes(data.try_into().unwrap()),
    })
}

fn read_u64(bytes: &[u8], offset: usize, endianness: ElfEndianness) -> Result<u64, Error> {
    let data = bytes
        .get(
            offset
                ..offset
                    .checked_add(8)
                    .ok_or(Error::Overflow("field offset"))?,
        )
        .ok_or(Error::OutOfBounds("ELF field"))?;
    Ok(match endianness {
        ElfEndianness::Little => u64::from_le_bytes(data.try_into().unwrap()),
        ElfEndianness::Big => u64::from_be_bytes(data.try_into().unwrap()),
    })
}
