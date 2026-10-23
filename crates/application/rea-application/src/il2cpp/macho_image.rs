//! Checked, read-only address mapping for caller-supplied Mach-O images.
//!
//! This module interprets a thin Mach-O header, its segment commands, and
//! their section tables. It never opens a file or consults a process, so all
//! addresses describe the supplied file image only.

use std::fmt;

const MACHO_MAGIC_32_BE: u32 = 0xfeed_face;
const MACHO_MAGIC_32_LE: u32 = 0xcefa_edfe;
const MACHO_MAGIC_64_BE: u32 = 0xfeed_facf;
const MACHO_MAGIC_64_LE: u32 = 0xcffa_edfe;
const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const MAX_LOAD_COMMAND_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEGMENTS: usize = 512;
const MAX_SECTIONS: usize = 16_384;
const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
const SECTION_TYPE_ZEROFILL: u32 = 0x0000_0001;
const SECTION_TYPE_GB_ZEROFILL: u32 = 0x0000_000c;
const SECTION_TYPE_THREAD_LOCAL_ZEROFILL: u32 = 0x0000_0012;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachClass {
    Mach32,
    Mach64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachEndian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachCpu {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
}

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
pub struct Protections {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub raw: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment {
    pub name: [u8; 16],
    pub vm_range: AddressRange,
    pub file_range: AddressRange,
    pub max_protections: Protections,
    pub initial_protections: Protections,
    pub sections: Vec<Section>,
}

impl Segment {
    /// Return the VM range backed by bytes in the captured file image.
    pub fn file_backed_vm_range(&self) -> Option<AddressRange> {
        let vm_size = self.vm_range.end.checked_sub(self.vm_range.start)?;
        let file_size = self.file_range.end.checked_sub(self.file_range.start)?;
        range(self.vm_range.start, vm_size.min(file_size))
    }

    /// Return only the segment file bytes that have a declared VM address.
    pub fn file_backed_file_range(&self) -> Option<AddressRange> {
        let vm_size = self.vm_range.end.checked_sub(self.vm_range.start)?;
        let file_size = self.file_range.end.checked_sub(self.file_range.start)?;
        range(self.file_range.start, vm_size.min(file_size))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    pub segment_name: [u8; 16],
    pub name: [u8; 16],
    pub vm_range: AddressRange,
    pub file_range: AddressRange,
    pub flags: u32,
}

impl Section {
    /// Return the section VM range that has corresponding source bytes.
    pub fn file_backed_vm_range(&self) -> Option<AddressRange> {
        let vm_size = self.vm_range.end.checked_sub(self.vm_range.start)?;
        let file_size = self.file_range.end.checked_sub(self.file_range.start)?;
        range(self.vm_range.start, vm_size.min(file_size))
    }

    /// Translate an address in this section to its captured source offset.
    pub fn file_offset_for_vm_address(&self, address: u64) -> Option<u64> {
        let vm_range = self.file_backed_vm_range()?;
        vm_range
            .contains(address)
            .then(|| self.file_range.start.checked_add(address - vm_range.start))?
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMapping {
    pub vm_address: u64,
    pub file_offset: u64,
    pub segment: usize,
    pub section: Option<usize>,
}

/// A normalized mapping owned by one Mach-O segment.
///
/// A segment can contain both bytes present in the file and trailing virtual
/// bytes (the usual `__bss` shape). Keeping the file range optional prevents a
/// virtual-only tail from being mistaken for readable input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageMapping {
    pub segment: usize,
    pub vm_range: AddressRange,
    pub file_range: Option<AddressRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingResolution {
    Unmapped,
    VirtualOnly,
    FileBacked(FileMapping),
    Ambiguous { candidate_count: usize },
}

/// A file-backed range in an executable segment. Section ownership is kept
/// when the section table identifies one; `None` means no unique section owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableFileMapping {
    pub segment: usize,
    pub section: Option<usize>,
    pub vm_range: AddressRange,
    pub file_range: AddressRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableMappingResolution {
    Unmapped,
    VirtualOnly,
    NonExecutable,
    FileBacked(ExecutableFileMapping),
    Ambiguous { candidate_count: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooSmall,
    UnsupportedMagic(u32),
    UniversalImage,
    InvalidHeader(&'static str),
    OutOfBounds(&'static str),
    Overflow(&'static str),
    CommandMismatch(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => formatter.write_str("Mach-O header is truncated"),
            Self::UnsupportedMagic(magic) => {
                write!(formatter, "unsupported Mach-O magic 0x{magic:08x}")
            }
            Self::UniversalImage => {
                formatter.write_str("universal Mach-O images require an architecture selection")
            }
            Self::InvalidHeader(reason) => write!(formatter, "invalid Mach-O header: {reason}"),
            Self::OutOfBounds(field) => {
                write!(formatter, "Mach-O {field} exceeds the supplied bytes")
            }
            Self::Overflow(field) => write!(formatter, "Mach-O {field} overflows"),
            Self::CommandMismatch(reason) => {
                write!(formatter, "Mach-O load command mismatch: {reason}")
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub struct MachOImage {
    class: MachClass,
    endian: MachEndian,
    cpu: MachCpu,
    file_type: u32,
    flags: u32,
    file_offset_base: u64,
    file_length: u64,
    segments: Vec<Segment>,
}

impl MachOImage {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse_with_file_offset_base(bytes, 0)
    }

    /// Parse a thin image whose bytes begin at `file_offset_base` in a larger
    /// source image, such as a selected universal Mach-O slice.
    ///
    /// Header fields are decoded from the supplied slice, while all exposed
    /// file ranges use source-image coordinates. This keeps address mappings
    /// useful to callers that retain the enclosing container and avoids
    /// silently treating a slice-relative offset as a source offset.
    pub fn parse_with_file_offset_base(bytes: &[u8], file_offset_base: u64) -> Result<Self, Error> {
        let mut image = Self::parse_slice(bytes)?;
        image.shift_file_offsets(file_offset_base)?;
        Ok(image)
    }

    fn parse_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::TooSmall);
        }

        let magic = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let (class, endian, header_size) = match magic {
            MACHO_MAGIC_32_LE => (MachClass::Mach32, MachEndian::Little, 28),
            MACHO_MAGIC_32_BE => (MachClass::Mach32, MachEndian::Big, 28),
            MACHO_MAGIC_64_LE => (MachClass::Mach64, MachEndian::Little, 32),
            MACHO_MAGIC_64_BE => (MachClass::Mach64, MachEndian::Big, 32),
            0xcafe_babe | 0xbeba_feca | 0xcafe_babf | 0xbfba_feca => {
                return Err(Error::UniversalImage);
            }
            other => return Err(Error::UnsupportedMagic(other)),
        };
        if bytes.len() < header_size {
            return Err(Error::TooSmall);
        }

        let cpu = MachCpu {
            cpu_type: read_u32(bytes, 4, endian)?,
            cpu_subtype: read_u32(bytes, 8, endian)?,
        };
        let file_type = read_u32(bytes, 12, endian)?;
        let command_count = usize::try_from(read_u32(bytes, 16, endian)?)
            .map_err(|_| Error::Overflow("load-command count"))?;
        let command_bytes = usize::try_from(read_u32(bytes, 20, endian)?)
            .map_err(|_| Error::Overflow("load-command size"))?;
        if command_bytes > MAX_LOAD_COMMAND_BYTES {
            return Err(Error::InvalidHeader("load-command area is too large"));
        }
        if command_count > MAX_SEGMENTS * 8 {
            return Err(Error::InvalidHeader("load-command count is unreasonable"));
        }
        let commands_end = checked_end(header_size, command_bytes, "load-command area")?;
        if commands_end > bytes.len() {
            return Err(Error::OutOfBounds("load-command area"));
        }

        let mut cursor = header_size;
        let mut segments = Vec::new();
        for _ in 0..command_count {
            let command = read_u32(bytes, cursor, endian)?;
            let command_size = usize::try_from(read_u32(bytes, cursor + 4, endian)?)
                .map_err(|_| Error::Overflow("load-command size"))?;
            if command_size < 8 || checked_end(cursor, command_size, "load command")? > commands_end
            {
                return Err(Error::CommandMismatch("command range is invalid"));
            }

            let base_command = command & 0x7fff_ffff;
            let parsed = if matches!(base_command, LC_SEGMENT | LC_SEGMENT_64) {
                let expected_command = match class {
                    MachClass::Mach32 => LC_SEGMENT,
                    MachClass::Mach64 => LC_SEGMENT_64,
                };
                if base_command != expected_command {
                    return Err(Error::CommandMismatch(
                        "segment command does not match header width",
                    ));
                }
                Some(parse_segment(
                    bytes,
                    cursor,
                    command_size,
                    endian,
                    class == MachClass::Mach64,
                )?)
            } else {
                None
            };
            if let Some(segment) = parsed {
                if segments.len() == MAX_SEGMENTS {
                    return Err(Error::InvalidHeader("too many segments"));
                }
                segments.push(segment);
            }
            cursor = checked_end(cursor, command_size, "load command")?;
        }
        if cursor != commands_end {
            return Err(Error::CommandMismatch(
                "command bytes disagree with command count",
            ));
        }

        Ok(Self {
            class,
            endian,
            cpu,
            file_type,
            flags: read_u32(bytes, 24, endian)?,
            file_offset_base: 0,
            file_length: bytes.len() as u64,
            segments,
        })
    }

    fn shift_file_offsets(&mut self, file_offset_base: u64) -> Result<(), Error> {
        for segment in &mut self.segments {
            segment.file_range = shift_range(segment.file_range, file_offset_base)?;

            for section in &mut segment.sections {
                section.file_range = shift_range(section.file_range, file_offset_base)?;
            }
        }

        self.file_offset_base = file_offset_base;
        self.file_length = file_offset_base
            .checked_add(self.file_length)
            .ok_or(Error::Overflow("source file length"))?;
        Ok(())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(bytes)
    }
    pub fn class(&self) -> MachClass {
        self.class
    }
    pub fn endian(&self) -> MachEndian {
        self.endian
    }
    pub fn cpu(&self) -> MachCpu {
        self.cpu
    }
    pub fn file_type(&self) -> u32 {
        self.file_type
    }
    pub fn flags(&self) -> u32 {
        self.flags
    }
    pub fn file_offset_base(&self) -> u64 {
        self.file_offset_base
    }
    pub fn file_length(&self) -> u64 {
        self.file_length
    }
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn vm_address_to_file_offset(&self, address: u64) -> Option<u64> {
        unique_mapping(self.segments.iter().map(|segment| {
            let vm = segment.file_backed_vm_range()?;
            (vm.contains(address))
                .then(|| segment.file_range.start.checked_add(address - vm.start))
                .flatten()
        }))
    }

    pub fn file_offset_to_vm_address(&self, offset: u64) -> Option<u64> {
        unique_mapping(self.segments.iter().map(|segment| {
            let file_range = segment.file_backed_file_range()?;
            file_range
                .contains(offset)
                .then(|| {
                    segment
                        .vm_range
                        .start
                        .checked_add(offset - file_range.start)
                })
                .flatten()
        }))
    }

    pub fn mapping_for_vm_address(&self, address: u64) -> Option<FileMapping> {
        let file_offset = self.vm_address_to_file_offset(address)?;
        let mut owner = None;
        for (segment_index, segment) in self.segments.iter().enumerate() {
            let Some(file_backed_vm) = segment.file_backed_vm_range() else {
                continue;
            };
            if !file_backed_vm.contains(address) {
                continue;
            }

            if owner.is_some() {
                return None;
            }

            let mut section_owner = None;
            for (section_index, section) in segment.sections.iter().enumerate() {
                if section
                    .file_backed_vm_range()
                    .is_some_and(|range| range.contains(address))
                {
                    if section_owner.is_some() {
                        return None;
                    }
                    if section.file_offset_for_vm_address(address) != Some(file_offset) {
                        return None;
                    }
                    section_owner = Some(section_index);
                }
            }

            owner = Some((segment_index, section_owner));
        }

        let (segment, section) = owner?;
        Some(FileMapping {
            vm_address: address,
            file_offset,
            segment,
            section,
        })
    }

    /// Return every segment mapping, retaining virtual-only tails explicitly.
    pub fn mappings(&self) -> Vec<ImageMapping> {
        self.segments
            .iter()
            .enumerate()
            .flat_map(|(segment, value)| {
                let file_backed = value.file_backed_vm_range();
                let mut mappings = Vec::with_capacity(2);

                if let Some(vm_range) = file_backed {
                    let file_size = vm_range.end - vm_range.start;
                    mappings.push(ImageMapping {
                        segment,
                        vm_range,
                        file_range: range(value.file_range.start, file_size),
                    });

                    if vm_range.end < value.vm_range.end {
                        mappings.push(ImageMapping {
                            segment,
                            vm_range: AddressRange {
                                start: vm_range.end,
                                end: value.vm_range.end,
                            },
                            file_range: None,
                        });
                    }
                } else if value.vm_range.start < value.vm_range.end {
                    mappings.push(ImageMapping {
                        segment,
                        vm_range: value.vm_range,
                        file_range: None,
                    });
                }

                mappings
            })
            .collect()
    }

    /// Return only the segment ranges whose bytes are present in the image.
    pub fn file_backed_mappings(&self) -> Vec<ImageMapping> {
        self.mappings()
            .into_iter()
            .filter(|mapping| mapping.file_range.is_some())
            .collect()
    }

    pub fn executable_ranges(&self) -> Vec<AddressRange> {
        self.segments
            .iter()
            .filter(|segment| segment.initial_protections.executable)
            .map(|segment| segment.vm_range)
            .collect()
    }

    /// Return executable ranges that can be read from the supplied image.
    /// Zero-fill tails are deliberately omitted because they contain no
    /// method-pointer bytes in the caller-owned snapshot.
    pub fn executable_file_backed_mappings(&self) -> Vec<ExecutableFileMapping> {
        let mut mappings = Vec::new();
        for (segment_index, segment) in self.segments.iter().enumerate() {
            if !segment.initial_protections.executable {
                continue;
            }
            let Some(file_backed_vm) = segment.file_backed_vm_range() else {
                continue;
            };
            let file_backed_size = file_backed_vm.end - file_backed_vm.start;

            if segment.sections.is_empty() {
                if let Some(file_range) = range(segment.file_range.start, file_backed_size) {
                    mappings.push(ExecutableFileMapping {
                        segment: segment_index,
                        section: None,
                        vm_range: file_backed_vm,
                        file_range,
                    });
                }
                continue;
            }

            let mut section_found = false;
            for (section_index, section) in segment.sections.iter().enumerate() {
                let Some(section_vm) = section.file_backed_vm_range() else {
                    continue;
                };
                let Some(vm_range) = intersect(file_backed_vm, section_vm) else {
                    continue;
                };
                let Some(file_start) = section.file_offset_for_vm_address(vm_range.start) else {
                    continue;
                };
                let size = vm_range.end - vm_range.start;
                let Some(file_range) = range(file_start, size) else {
                    continue;
                };
                section_found = true;
                mappings.push(ExecutableFileMapping {
                    segment: segment_index,
                    section: Some(section_index),
                    vm_range,
                    file_range,
                });
            }

            if !section_found {
                if let Some(file_range) = range(segment.file_range.start, file_backed_size) {
                    mappings.push(ExecutableFileMapping {
                        segment: segment_index,
                        section: None,
                        vm_range: file_backed_vm,
                        file_range,
                    });
                }
            }
        }
        mappings
    }

    /// Resolve an address against executable, file-backed ranges while
    /// retaining zero-fill, non-executable, and overlap states.
    pub fn resolve_executable_vm_address(&self, address: u64) -> ExecutableMappingResolution {
        let contained = self
            .segments
            .iter()
            .filter(|segment| segment.vm_range.contains(address))
            .collect::<Vec<_>>();
        if contained.is_empty() {
            return ExecutableMappingResolution::Unmapped;
        }

        let executable = self
            .executable_file_backed_mappings()
            .into_iter()
            .filter(|mapping| mapping.vm_range.contains(address))
            .collect::<Vec<_>>();
        match executable.as_slice() {
            [mapping] => ExecutableMappingResolution::FileBacked(*mapping),
            [] => {
                if contained.iter().any(|segment| {
                    segment.initial_protections.executable
                        && segment
                            .file_backed_vm_range()
                            .is_none_or(|range| !range.contains(address))
                }) {
                    ExecutableMappingResolution::VirtualOnly
                } else {
                    ExecutableMappingResolution::NonExecutable
                }
            }
            _ => ExecutableMappingResolution::Ambiguous {
                candidate_count: executable.len(),
            },
        }
    }

    /// Resolve an address while distinguishing absent, virtual-only, and
    /// ambiguous mappings. `mapping_for_vm_address` remains available for
    /// callers that only need a unique file-backed translation.
    pub fn resolve_vm_address(&self, address: u64) -> MappingResolution {
        let mut candidates = Vec::new();
        for (segment_index, segment) in self.segments.iter().enumerate() {
            if !segment.vm_range.contains(address) {
                continue;
            }

            let file_mapping = segment.file_backed_vm_range().and_then(|range| {
                if !range.contains(address) {
                    return None;
                }

                let file_offset = segment.file_range.start + (address - range.start);
                let mut matching_sections = segment
                    .sections
                    .iter()
                    .enumerate()
                    .filter(|(_, section)| {
                        section
                            .file_backed_vm_range()
                            .is_some_and(|range| range.contains(address))
                    })
                    .map(|(index, _)| index);
                let section = match (matching_sections.next(), matching_sections.next()) {
                    (None, _) => None,
                    (Some(index), None) => Some(index),
                    (Some(_), Some(_)) => Some(usize::MAX),
                };
                Some(FileMapping {
                    vm_address: address,
                    file_offset,
                    segment: segment_index,
                    section,
                })
            });
            candidates.push(file_mapping);
        }

        match candidates.as_slice() {
            [] => MappingResolution::Unmapped,
            [Some(mapping)] => MappingResolution::FileBacked(*mapping),
            [None] => MappingResolution::VirtualOnly,
            _ => MappingResolution::Ambiguous {
                candidate_count: candidates.len(),
            },
        }
    }
}

fn parse_segment(
    bytes: &[u8],
    offset: usize,
    command_size: usize,
    endian: MachEndian,
    wide: bool,
) -> Result<Segment, Error> {
    let command_header = if wide { 72 } else { 56 };
    let section_size = if wide { 80 } else { 68 };
    if command_size < command_header {
        return Err(Error::CommandMismatch("segment command is truncated"));
    }
    let name = read_name(bytes, offset + 8)?;
    let vm_start = read_word(bytes, offset + 24, endian, wide)?;
    let vm_size = read_word(bytes, offset + 24 + if wide { 8 } else { 4 }, endian, wide)?;
    let file_start = read_word(bytes, offset + 32 + if wide { 8 } else { 0 }, endian, wide)?;
    let file_size = read_word(bytes, offset + 36 + if wide { 12 } else { 0 }, endian, wide)?;
    let max_protection = read_u32(bytes, offset + 40 + if wide { 16 } else { 0 }, endian)?;
    let initial_protection = read_u32(bytes, offset + 44 + if wide { 16 } else { 0 }, endian)?;
    let section_count = usize::try_from(read_u32(
        bytes,
        offset + 48 + if wide { 16 } else { 0 },
        endian,
    )?)
    .map_err(|_| Error::Overflow("section count"))?;
    if section_count > MAX_SECTIONS
        || section_count
            .checked_mul(section_size)
            .and_then(|size| command_header.checked_add(size))
            .is_none_or(|size| size > command_size)
    {
        return Err(Error::CommandMismatch(
            "section table exceeds segment command",
        ));
    }
    let vm_range = range(vm_start, vm_size).ok_or(Error::Overflow("segment VM range"))?;
    let file_range = range(file_start, file_size).ok_or(Error::Overflow("segment file range"))?;
    if file_range.end > bytes.len() as u64 {
        return Err(Error::OutOfBounds("segment file range"));
    }

    let mut sections = Vec::with_capacity(section_count);
    let section_offset = offset + command_header;
    for index in 0..section_count {
        let at = section_offset + index * section_size;
        let section_name = read_name(bytes, at)?;
        let section_segment_name = read_name(bytes, at + 16)?;
        let (address, size, raw_offset, flags_offset) = if wide {
            (
                read_u64(bytes, at + 32, endian)?,
                read_u64(bytes, at + 40, endian)?,
                read_u32(bytes, at + 48, endian)?,
                at + 64,
            )
        } else {
            (
                u64::from(read_u32(bytes, at + 32, endian)?),
                u64::from(read_u32(bytes, at + 36, endian)?),
                read_u32(bytes, at + 40, endian)?,
                at + 56,
            )
        };
        let flags = read_u32(bytes, flags_offset, endian)?;
        let section_range = range(address, size).ok_or(Error::Overflow("section VM range"))?;
        let section_type = flags & SECTION_TYPE_MASK;
        let section_file_range = if matches!(
            section_type,
            SECTION_TYPE_ZEROFILL | SECTION_TYPE_GB_ZEROFILL | SECTION_TYPE_THREAD_LOCAL_ZEROFILL
        ) {
            // Zerofill sections occupy VM space but have no bytes in the file.
            AddressRange {
                start: u64::from(raw_offset),
                end: u64::from(raw_offset),
            }
        } else {
            // Preserve the declared extent; malformed sections must not become
            // apparently valid mappings by truncating to the segment size.
            if size > file_size {
                return Err(Error::CommandMismatch(
                    "section file size exceeds its segment file size",
                ));
            }
            let section_file_range =
                range(u64::from(raw_offset), size).ok_or(Error::Overflow("section file range"))?;
            if section_file_range.end > bytes.len() as u64 {
                return Err(Error::OutOfBounds("section file range"));
            }
            if section_file_range.start < file_range.start
                || section_file_range.end > file_range.end
            {
                return Err(Error::CommandMismatch(
                    "section file range is outside its segment",
                ));
            }
            section_file_range
        };
        if section_range.start < vm_range.start || section_range.end > vm_range.end {
            return Err(Error::CommandMismatch(
                "section VM range is outside its segment",
            ));
        }
        sections.push(Section {
            segment_name: section_segment_name,
            name: section_name,
            vm_range: section_range,
            file_range: section_file_range,
            flags,
        });
    }
    Ok(Segment {
        name,
        vm_range,
        file_range,
        max_protections: protections(max_protection),
        initial_protections: protections(initial_protection),
        sections,
    })
}

fn protections(raw: u32) -> Protections {
    Protections {
        readable: raw & 1 != 0,
        writable: raw & 2 != 0,
        executable: raw & 4 != 0,
        raw,
    }
}
fn read_name(bytes: &[u8], offset: usize) -> Result<[u8; 16], Error> {
    bytes
        .get(offset..checked_end(offset, 16, "name")?)
        .ok_or(Error::OutOfBounds("name"))?
        .try_into()
        .map_err(|_| Error::InvalidHeader("name is truncated"))
}
fn read_word(bytes: &[u8], offset: usize, endian: MachEndian, wide: bool) -> Result<u64, Error> {
    if wide {
        read_u64(bytes, offset, endian)
    } else {
        read_u32(bytes, offset, endian).map(u64::from)
    }
}
fn read_u32(bytes: &[u8], offset: usize, endian: MachEndian) -> Result<u32, Error> {
    let data = bytes
        .get(offset..checked_end(offset, 4, "field")?)
        .ok_or(Error::OutOfBounds("field"))?;
    Ok(match endian {
        MachEndian::Little => u32::from_le_bytes(data.try_into().unwrap()),
        MachEndian::Big => u32::from_be_bytes(data.try_into().unwrap()),
    })
}
fn read_u64(bytes: &[u8], offset: usize, endian: MachEndian) -> Result<u64, Error> {
    let data = bytes
        .get(offset..checked_end(offset, 8, "field")?)
        .ok_or(Error::OutOfBounds("field"))?;
    Ok(match endian {
        MachEndian::Little => u64::from_le_bytes(data.try_into().unwrap()),
        MachEndian::Big => u64::from_be_bytes(data.try_into().unwrap()),
    })
}
fn checked_end(start: usize, size: usize, field: &'static str) -> Result<usize, Error> {
    start.checked_add(size).ok_or(Error::Overflow(field))
}
fn range(start: u64, size: u64) -> Option<AddressRange> {
    Some(AddressRange {
        start,
        end: start.checked_add(size)?,
    })
}

fn shift_range(value: AddressRange, base: u64) -> Result<AddressRange, Error> {
    Ok(AddressRange {
        start: value
            .start
            .checked_add(base)
            .ok_or(Error::Overflow("source file range"))?,
        end: value
            .end
            .checked_add(base)
            .ok_or(Error::Overflow("source file range"))?,
    })
}

fn intersect(left: AddressRange, right: AddressRange) -> Option<AddressRange> {
    let start = left.start.max(right.start);
    let end = left.end.min(right.end);
    (start < end).then_some(AddressRange { start, end })
}

fn unique_mapping(values: impl Iterator<Item = Option<u64>>) -> Option<u64> {
    let mut result = None;
    for value in values.flatten() {
        if result.is_some() {
            return None;
        }
        result = Some(value);
    }
    result
}
