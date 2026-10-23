//! Checked, read-only address mapping for caller-supplied PE images.
//!
//! The mapper interprets only PE headers and section tables in the supplied
//! bytes. It never loads an image or consults process state, so every mapping
//! remains a file-image observation rather than a statement about runtime
//! memory.

use std::fmt;

const PE_MAGIC: &[u8; 4] = b"PE\0\0";
const DOS_HEADER_SIZE: usize = 64;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const MAX_SECTIONS: usize = 96;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_ALIGN_MASK: u32 = 0x0060_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeClass {
    Pe32,
    Pe32Plus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeMachine(pub u16);

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
pub struct SectionPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub file_offset: u32,
    pub file_size: u32,
    pub characteristics: u32,
    pub permissions: SectionPermissions,
}

impl Section {
    pub fn file_range(&self) -> Option<AddressRange> {
        range(u64::from(self.file_offset), u64::from(self.file_size))
    }

    pub fn rva_range(&self) -> Option<AddressRange> {
        range(
            u64::from(self.virtual_address),
            u64::from(self.virtual_extent()),
        )
    }

    pub fn file_backed_rva_range(&self) -> Option<AddressRange> {
        range(
            u64::from(self.virtual_address),
            u64::from(self.virtual_extent().min(self.file_size)),
        )
    }

    pub fn executable_rva_range(&self) -> Option<AddressRange> {
        self.permissions
            .executable
            .then(|| self.rva_range())
            .flatten()
    }

    fn virtual_extent(&self) -> u32 {
        if self.virtual_size == 0 {
            self.file_size
        } else {
            self.virtual_size
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMapping {
    pub rva: u64,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub section: usize,
}

/// A complete, file-backed section mapping in image coordinates.
///
/// The range deliberately ends at the raw file-backed extent.  Zero-fill
/// tails remain visible through [`Section::rva_range`] but cannot be used to
/// read a CodeGenModule record or a method-pointer table from the capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileBackedMapping {
    pub virtual_start: u64,
    pub virtual_end: u64,
    pub file_start: u64,
    pub file_end: u64,
    pub section: usize,
}

/// File-backed coordinates for an executable method-pointer target.
///
/// `virtual_range` describes the complete PE section extent, while
/// `file_backed_virtual_range` describes the portion for which the supplied
/// capture contains bytes. Keeping both ranges lets callers report a
/// zero-fill hit without treating it as a readable method body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableMethodPointerMapping {
    pub section: usize,
    pub virtual_range: AddressRange,
    pub file_backed_virtual_range: AddressRange,
    pub raw_file_range: AddressRange,
    pub file_range: AddressRange,
}

/// A file-backed initialized data section selected by the PE reader.
///
/// This is the bounded equivalent of the TypeScript image reader's data
/// search mapping. Both coordinate systems remain explicit so consumers do
/// not have to reconstruct a virtual address from a file offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializedDataMapping {
    pub rva: u64,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub section: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooSmall,
    InvalidDosMagic,
    InvalidPeSignature,
    InvalidHeader(&'static str),
    OutOfBounds(&'static str),
    Overflow(&'static str),
    UnsupportedOptionalHeader(u16),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => formatter.write_str("PE header is truncated"),
            Self::InvalidDosMagic => formatter.write_str("DOS magic is invalid"),
            Self::InvalidPeSignature => formatter.write_str("PE signature is invalid"),
            Self::InvalidHeader(reason) => write!(formatter, "invalid PE header: {reason}"),
            Self::OutOfBounds(field) => write!(formatter, "PE {field} exceeds the supplied bytes"),
            Self::Overflow(field) => write!(formatter, "PE {field} overflows"),
            Self::UnsupportedOptionalHeader(magic) => {
                write!(
                    formatter,
                    "unsupported PE optional-header magic 0x{magic:04x}"
                )
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeImage {
    class: PeClass,
    machine: PeMachine,
    image_base: u64,
    size_of_image: u32,
    size_of_headers: u32,
    file_length: u64,
    sections: Vec<Section>,
}

impl PeImage {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < DOS_HEADER_SIZE {
            return Err(Error::TooSmall);
        }
        if &bytes[..2] != b"MZ" {
            return Err(Error::InvalidDosMagic);
        }

        let pe_offset = usize::try_from(read_u32(bytes, 0x3c)?)
            .map_err(|_| Error::Overflow("PE header offset"))?;
        if pe_offset < DOS_HEADER_SIZE {
            return Err(Error::InvalidHeader("PE header overlaps the DOS header"));
        }
        let signature_end = checked_end(pe_offset, 4, "PE signature")?;
        if signature_end > bytes.len() {
            return Err(Error::OutOfBounds("signature"));
        }
        if &bytes[pe_offset..signature_end] != PE_MAGIC {
            return Err(Error::InvalidPeSignature);
        }

        let coff_offset = checked_end(pe_offset, 4, "COFF header")?;
        let coff_end = checked_end(coff_offset, COFF_HEADER_SIZE, "COFF header")?;
        if coff_end > bytes.len() {
            return Err(Error::OutOfBounds("COFF header"));
        }
        let machine = PeMachine(read_u16(bytes, coff_offset)?);
        let section_count = usize::from(read_u16(bytes, coff_offset + 2)?);
        if section_count == 0 || section_count > MAX_SECTIONS {
            return Err(Error::InvalidHeader("section count is unreasonable"));
        }
        let optional_size = usize::from(read_u16(bytes, coff_offset + 16)?);
        if optional_size < 2 {
            return Err(Error::InvalidHeader("optional header is too small"));
        }
        let optional_offset = coff_end;
        let optional_end = checked_end(optional_offset, optional_size, "optional header")?;
        if optional_end > bytes.len() {
            return Err(Error::OutOfBounds("optional header"));
        }

        let magic = read_u16(bytes, optional_offset)?;
        let (class, image_base_offset, size_of_image_offset, size_of_headers_offset) = match magic {
            PE32_MAGIC => (PeClass::Pe32, 28usize, 56usize, 60usize),
            PE32_PLUS_MAGIC => (PeClass::Pe32Plus, 24usize, 56usize, 60usize),
            value => return Err(Error::UnsupportedOptionalHeader(value)),
        };
        if image_base_offset + if class == PeClass::Pe32 { 4 } else { 8 } > optional_size
            || size_of_headers_offset + 4 > optional_size
        {
            return Err(Error::InvalidHeader("optional header fields are truncated"));
        }
        let image_base = match class {
            PeClass::Pe32 => u64::from(read_u32(bytes, optional_offset + image_base_offset)?),
            PeClass::Pe32Plus => read_u64(bytes, optional_offset + image_base_offset)?,
        };
        let size_of_image = read_u32(bytes, optional_offset + size_of_image_offset)?;
        let size_of_headers = read_u32(bytes, optional_offset + size_of_headers_offset)?;
        let section_table_end = checked_table_end(
            optional_end,
            SECTION_HEADER_SIZE,
            section_count,
            "section table",
        )?;
        if section_table_end > bytes.len() {
            return Err(Error::OutOfBounds("section table"));
        }
        if size_of_image == 0 {
            return Err(Error::InvalidHeader("image size is zero"));
        }
        if image_base.checked_add(u64::from(size_of_image)).is_none() {
            return Err(Error::Overflow("image address range"));
        }
        if u64::from(size_of_headers) < section_table_end as u64
            || u64::from(size_of_headers) > bytes.len() as u64
            || size_of_headers > size_of_image
        {
            return Err(Error::InvalidHeader(
                "declared headers do not fit the captured image",
            ));
        }

        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let offset = optional_end
                .checked_add(
                    index
                        .checked_mul(SECTION_HEADER_SIZE)
                        .ok_or(Error::Overflow("section index"))?,
                )
                .ok_or(Error::Overflow("section offset"))?;
            let section = read_section(bytes, offset)?;
            validate_section(
                &section,
                bytes.len() as u64,
                size_of_headers,
                size_of_image,
                image_base,
                class,
            )?;
            sections.push(section);
        }
        validate_file_sections(&sections)?;
        validate_virtual_sections(&sections, size_of_headers)?;

        Ok(Self {
            class,
            machine,
            image_base,
            size_of_image,
            size_of_headers,
            file_length: bytes.len() as u64,
            sections,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(bytes)
    }

    pub fn class(&self) -> PeClass {
        self.class
    }
    pub fn machine(&self) -> PeMachine {
        self.machine
    }
    pub fn image_base(&self) -> u64 {
        self.image_base
    }
    pub fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Locate the unique linker data section.
    ///
    /// The selection mirrors the existing TypeScript PE reader: the section
    /// must be readable, writable, and initialized data, while alignment bits
    /// are ignored. Section order is preserved, and only bytes backed by the
    /// supplied file are admitted. No runtime load address is inferred.
    pub fn initialized_data_mappings(&self) -> Vec<InitializedDataMapping> {
        self.sections
            .iter()
            .enumerate()
            .filter_map(|(section, candidate)| {
                let characteristics = candidate.characteristics;
                let matches_data_flags = characteristics & !IMAGE_SCN_ALIGN_MASK
                    == IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
                let file_size = u64::from(candidate.virtual_extent().min(candidate.file_size));
                if !matches_data_flags
                    || candidate.virtual_address == 0
                    || candidate.file_size == 0
                    || file_size == 0
                {
                    return None;
                }

                Some(InitializedDataMapping {
                    rva: u64::from(candidate.virtual_address),
                    virtual_address: self
                        .image_base
                        .checked_add(u64::from(candidate.virtual_address))?,
                    file_offset: u64::from(candidate.file_offset),
                    file_size,
                    section,
                })
            })
            .collect()
    }

    /// Return the initialized data mapping only when the image has one.
    ///
    /// Multiple initialized data sections are retained by
    /// [`Self::initialized_data_mappings`]; this convenience method refuses
    /// to choose between them.
    pub fn initialized_data_mapping(&self) -> Option<InitializedDataMapping> {
        let mut mappings = self.initialized_data_mappings().into_iter();
        let mapping = mappings.next()?;
        mappings.next().is_none().then_some(mapping)
    }

    /// Return every section interval whose bytes are backed by the capture.
    ///
    /// Entries are kept in PE section-table order.  Overlapping virtual
    /// intervals are not silently merged, allowing consumers to preserve an
    /// ambiguous ownership result when a malformed or unusual image exposes
    /// more than one mapping for an address.
    pub fn file_backed_mappings(&self) -> Vec<FileBackedMapping> {
        self.sections
            .iter()
            .enumerate()
            .filter_map(|(section, candidate)| {
                let rva = candidate.file_backed_rva_range()?;
                let file = candidate.file_range()?;
                let file_end = file.start.checked_add(rva.end - rva.start)?;
                Some(FileBackedMapping {
                    virtual_start: self.image_base.checked_add(rva.start)?,
                    virtual_end: self.image_base.checked_add(rva.end)?,
                    file_start: file.start,
                    file_end,
                    section,
                })
            })
            .collect()
    }

    /// Return every executable section that can provide `byte_length` bytes
    /// for a method-pointer target at `address`.
    ///
    /// A target in the zero-fill tail is deliberately excluded. Multiple
    /// qualifying sections remain separate so the caller can preserve
    /// ambiguity instead of selecting one by section-table order.
    pub fn executable_method_pointer_mappings(
        &self,
        address: u64,
        byte_length: u64,
    ) -> Vec<ExecutableMethodPointerMapping> {
        let Some(end) = address.checked_add(byte_length) else {
            return Vec::new();
        };
        if byte_length == 0 {
            return Vec::new();
        }

        self.sections
            .iter()
            .enumerate()
            .filter_map(|(section, candidate)| {
                if !candidate.permissions.executable {
                    return None;
                }

                let section_rva = candidate.rva_range()?;
                let file_backed_rva = candidate.file_backed_rva_range()?;
                let virtual_start = self.image_base.checked_add(section_rva.start)?;
                let file_backed_start = self.image_base.checked_add(file_backed_rva.start)?;
                let virtual_range = AddressRange {
                    start: virtual_start,
                    end: self.image_base.checked_add(section_rva.end)?,
                };
                let file_backed_virtual_range = AddressRange {
                    start: file_backed_start,
                    end: self.image_base.checked_add(file_backed_rva.end)?,
                };
                if !virtual_range.contains(address)
                    || end > file_backed_virtual_range.end
                    || address < file_backed_virtual_range.start
                {
                    return None;
                }

                let file_start = u64::from(candidate.file_offset)
                    .checked_add(address - file_backed_virtual_range.start)?;
                let file_range = AddressRange {
                    start: file_start,
                    end: file_start.checked_add(byte_length)?,
                };
                let raw_file_range = candidate.file_range()?;

                Some(ExecutableMethodPointerMapping {
                    section,
                    virtual_range,
                    file_backed_virtual_range,
                    raw_file_range,
                    file_range,
                })
            })
            .collect()
    }

    /// Resolve one executable method-pointer target only when its mapping is
    /// unique. A target covered by multiple executable sections remains
    /// unresolved.
    pub fn executable_method_pointer_mapping(
        &self,
        address: u64,
        byte_length: u64,
    ) -> Option<ExecutableMethodPointerMapping> {
        let mut mappings = self
            .executable_method_pointer_mappings(address, byte_length)
            .into_iter();
        let mapping = mappings.next()?;
        mappings.next().is_none().then_some(mapping)
    }

    pub fn rva_to_file_offset(&self, rva: u64) -> Option<u64> {
        let header_mapping =
            (rva < u64::from(self.size_of_headers) && rva < self.file_length).then_some(rva);
        unique_mapping(
            header_mapping
                .into_iter()
                .map(Some)
                .chain(self.sections.iter().map(|section| {
                    let range = section.file_backed_rva_range()?;
                    range
                        .contains(rva)
                        .then(|| u64::from(section.file_offset).checked_add(rva - range.start))
                        .flatten()
                })),
        )
    }

    pub fn va_to_file_offset(&self, address: u64) -> Option<u64> {
        self.virtual_address_to_file_offset(address)
    }

    pub fn file_offset_to_rva(&self, offset: u64) -> Option<u64> {
        let header_mapping = (offset < u64::from(self.size_of_headers)
            && offset < self.file_length)
            .then_some(offset);
        unique_mapping(
            header_mapping
                .into_iter()
                .map(Some)
                .chain(self.sections.iter().map(|section| {
                    let rva_range = section.file_backed_rva_range()?;
                    let file_range = range(
                        u64::from(section.file_offset),
                        rva_range.end - rva_range.start,
                    )?;
                    file_range
                        .contains(offset)
                        .then(|| {
                            u64::from(section.virtual_address)
                                .checked_add(offset - file_range.start)
                        })
                        .flatten()
                })),
        )
    }

    pub fn file_offset_to_va(&self, offset: u64) -> Option<u64> {
        self.file_offset_to_virtual_address(offset)
    }

    pub fn virtual_address_to_file_offset(&self, address: u64) -> Option<u64> {
        let rva = address.checked_sub(self.image_base)?;
        self.rva_to_file_offset(rva)
    }

    pub fn file_offset_to_virtual_address(&self, offset: u64) -> Option<u64> {
        self.file_offset_to_rva(offset)?
            .checked_add(self.image_base)
    }

    /// Check an image-relative virtual range without claiming a runtime load.
    ///
    /// The TypeScript PE reader uses the same half-open image extent for
    /// address admission. Keeping this predicate on the parsed image avoids
    /// callers rebuilding the base-plus-size arithmetic themselves.
    pub fn has_image_range(&self, start: u64, end: u64) -> bool {
        if end < start || start < self.image_base {
            return false;
        }

        end.checked_sub(self.image_base)
            .is_some_and(|extent| extent <= u64::from(self.size_of_image))
    }

    /// Report whether an image virtual address belongs to executable section
    /// space. This includes zero-fill tails, matching loader section
    /// membership rather than file-backed instruction availability.
    pub fn is_executable(&self, address: u64) -> bool {
        let Some(rva) = address.checked_sub(self.image_base) else {
            return false;
        };

        self.sections.iter().any(|section| {
            if !section.permissions.executable {
                return false;
            }

            section.rva_range().is_some_and(|range| range.contains(rva))
        })
    }

    /// Return the remaining virtual bytes in the section containing an
    /// address, including zero-fill bytes after the raw section data.
    pub fn virtual_bytes_remaining(&self, address: u64) -> u64 {
        let Some(rva) = address.checked_sub(self.image_base) else {
            return 0;
        };

        self.sections
            .iter()
            .find_map(|section| {
                let range = section.rva_range()?;
                if !range.contains(rva) {
                    return None;
                }

                range.end.checked_sub(rva)
            })
            .unwrap_or(0)
    }

    pub fn mapping_for_rva(&self, rva: u64) -> Option<FileMapping> {
        let file_offset = self.rva_to_file_offset(rva)?;
        let mut section = None;
        for (index, candidate) in self.sections.iter().enumerate() {
            if candidate
                .file_backed_rva_range()
                .is_some_and(|range| range.contains(rva))
            {
                if section.is_some() {
                    return None;
                }
                section = Some(index);
            }
        }
        Some(FileMapping {
            rva,
            virtual_address: self.image_base.checked_add(rva)?,
            file_offset,
            section: section.unwrap_or(usize::MAX),
        })
    }

    pub fn executable_rva_ranges(&self) -> Vec<AddressRange> {
        self.sections
            .iter()
            .filter_map(|section| section.executable_rva_range())
            .collect()
    }

    pub fn executable_range_containing(&self, rva: u64) -> Option<AddressRange> {
        unique_range(
            self.executable_rva_ranges()
                .into_iter()
                .filter(|range| range.contains(rva)),
        )
    }

    pub fn executable_virtual_range_containing(&self, address: u64) -> Option<AddressRange> {
        let rva = address.checked_sub(self.image_base)?;
        let range = self.executable_range_containing(rva)?;
        Some(AddressRange {
            start: self.image_base.checked_add(range.start)?,
            end: self.image_base.checked_add(range.end)?,
        })
    }
}

fn read_section(bytes: &[u8], offset: usize) -> Result<Section, Error> {
    let name = bytes
        .get(offset..checked_end(offset, 8, "section name")?)
        .ok_or(Error::OutOfBounds("section"))?
        .try_into()
        .map_err(|_| Error::InvalidHeader("section name is truncated"))?;
    let virtual_size = read_u32(bytes, offset + 8)?;
    let virtual_address = read_u32(bytes, offset + 12)?;
    let file_size = read_u32(bytes, offset + 16)?;
    let file_offset = read_u32(bytes, offset + 20)?;
    let characteristics = read_u32(bytes, offset + 36)?;
    Ok(Section {
        name,
        virtual_address,
        virtual_size,
        file_offset,
        file_size,
        characteristics,
        permissions: SectionPermissions {
            readable: characteristics & IMAGE_SCN_MEM_READ != 0,
            writable: characteristics & IMAGE_SCN_MEM_WRITE != 0,
            executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        },
    })
}

fn validate_section(
    section: &Section,
    length: u64,
    size_of_headers: u32,
    size_of_image: u32,
    image_base: u64,
    class: PeClass,
) -> Result<(), Error> {
    let file_end = u64::from(section.file_offset)
        .checked_add(u64::from(section.file_size))
        .ok_or(Error::Overflow("section file range"))?;
    if file_end > length {
        return Err(Error::OutOfBounds("section data"));
    }
    if section.file_size > 0 && section.file_offset < size_of_headers {
        return Err(Error::InvalidHeader("section data overlaps headers"));
    }
    let virtual_size = u64::from(section.virtual_extent());
    u64::from(section.virtual_address)
        .checked_add(virtual_size)
        .ok_or(Error::Overflow("section RVA range"))?;
    if u64::from(section.virtual_address) + virtual_size > u64::from(size_of_image) {
        return Err(Error::InvalidHeader("section exceeds image size"));
    }

    let declared_extent = u64::from(section.virtual_size.max(section.file_size));
    let section_address = image_base
        .checked_add(u64::from(section.virtual_address))
        .ok_or(Error::Overflow("section address range"))?;
    let section_address_end = section_address
        .checked_add(declared_extent)
        .ok_or(Error::Overflow("section address range"))?;
    if class == PeClass::Pe32 && section_address_end > (1u64 << 32) {
        return Err(Error::InvalidHeader(
            "section exceeds the PE32 address width",
        ));
    }

    Ok(())
}

fn validate_virtual_sections(sections: &[Section], size_of_headers: u32) -> Result<(), Error> {
    let mut mapped = sections
        .iter()
        .cloned()
        .filter(|section| section.virtual_extent() > 0)
        .collect::<Vec<_>>();
    mapped.sort_by_key(|section| section.virtual_address);

    let mut mapped_end = u64::from(size_of_headers);
    for section in mapped {
        let start = u64::from(section.virtual_address);
        if start < mapped_end {
            return Err(Error::InvalidHeader(
                "section overlaps headers or another section",
            ));
        }
        mapped_end = start + u64::from(section.virtual_extent());
    }
    Ok(())
}

fn validate_file_sections(sections: &[Section]) -> Result<(), Error> {
    let mut backed = sections
        .iter()
        .cloned()
        .filter(|section| section.file_size > 0)
        .collect::<Vec<_>>();
    backed.sort_by_key(|section| section.file_offset);

    let mut previous_end = None;
    for section in backed {
        let start = u64::from(section.file_offset);
        let end = start + u64::from(section.file_size);
        if previous_end.is_some_and(|end| start < end) {
            return Err(Error::InvalidHeader("section raw ranges overlap"));
        }
        previous_end = Some(end);
    }

    Ok(())
}

fn checked_end(start: usize, size: usize, field: &'static str) -> Result<usize, Error> {
    start.checked_add(size).ok_or(Error::Overflow(field))
}

fn checked_table_end(
    start: usize,
    entry_size: usize,
    count: usize,
    field: &'static str,
) -> Result<usize, Error> {
    let bytes = entry_size
        .checked_mul(count)
        .ok_or(Error::Overflow(field))?;
    checked_end(start, bytes, field)
}

fn range(start: u64, size: u64) -> Option<AddressRange> {
    Some(AddressRange {
        start,
        end: start.checked_add(size)?,
    })
}

fn unique_mapping(values: impl Iterator<Item = Option<u64>>) -> Option<u64> {
    let mut result = None;
    let mut matches = 0usize;
    for value in values.flatten() {
        matches = matches.checked_add(1)?;
        result = Some(value);
    }

    if matches == 1 { result } else { None }
}

fn unique_range(values: impl Iterator<Item = AddressRange>) -> Option<AddressRange> {
    let mut result = None;
    let mut matches = 0usize;
    for value in values {
        matches = matches.checked_add(1)?;
        result = Some(value);
    }

    if matches == 1 { result } else { None }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let data = bytes
        .get(offset..checked_end(offset, 2, "field offset")?)
        .ok_or(Error::OutOfBounds("field"))?;
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let data = bytes
        .get(offset..checked_end(offset, 4, "field offset")?)
        .ok_or(Error::OutOfBounds("field"))?;
    Ok(u32::from_le_bytes(data.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let data = bytes
        .get(offset..checked_end(offset, 8, "field offset")?)
        .ok_or(Error::OutOfBounds("field"))?;
    Ok(u64::from_le_bytes(data.try_into().unwrap()))
}
