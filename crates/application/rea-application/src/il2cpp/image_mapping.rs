//! Format-neutral mapping for caller-supplied IL2CPP native images.
//!
//! This module is deliberately a small composition boundary.  The ELF and PE
//! decoders own format interpretation; this layer only turns their checked
//! records into a stable image description.  It never opens a path, loads an
//! image, or consults process state.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageFormat {
    Elf,
    MachO,
    Pe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedSegment {
    pub index: usize,
    pub name: Option<String>,
    pub file_offset: u64,
    pub file_size: u64,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub readable: Option<bool>,
    pub writable: Option<bool>,
    pub executable: bool,
    pub format_details: FormatDetails,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FormatDetails {
    Elf {
        flags: u32,
        alignment: u64,
    },
    Pe {
        characteristics: u32,
        section_name: [u8; 8],
    },
    MachO {
        raw_name: Vec<u8>,
        protections: Option<u32>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedImage {
    pub format: ImageFormat,
    pub architecture: u64,
    pub image_base: Option<u64>,
    pub segments: Vec<NormalizedSegment>,
    pub executable_ranges: Vec<AddressRange>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyInput,
    UnsupportedFormat,
    MachOMapperUnavailable,
    Elf(String),
    Pe(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("native image input is empty"),
            Self::UnsupportedFormat => formatter.write_str("native image format is unsupported"),
            Self::MachOMapperUnavailable => formatter
                .write_str("Mach-O image mapping requires the checked Mach-O mapper integration"),
            Self::Elf(error) => write!(formatter, "ELF image mapping failed: {error}"),
            Self::Pe(error) => write!(formatter, "PE image mapping failed: {error}"),
        }
    }
}

/// Decode a caller-supplied native image into the format-neutral mapping.
pub fn map_image(bytes: &[u8]) -> Result<NormalizedImage, Error> {
    if bytes.is_empty() {
        return Err(Error::EmptyInput);
    }

    if bytes.starts_with(b"\x7fELF") {
        return map_elf(bytes);
    }

    if bytes.starts_with(b"MZ") {
        return map_pe(bytes);
    }

    if is_macho_magic(bytes) {
        return Err(Error::MachOMapperUnavailable);
    }

    Err(Error::UnsupportedFormat)
}

pub fn parse(bytes: &[u8]) -> Result<NormalizedImage, Error> {
    map_image(bytes)
}

fn map_elf(bytes: &[u8]) -> Result<NormalizedImage, Error> {
    let image =
        super::elf_image::ElfImage::parse(bytes).map_err(|error| Error::Elf(error.to_string()))?;
    let segments = image
        .load_segments()
        .iter()
        .copied()
        .enumerate()
        .map(|(index, segment)| NormalizedSegment {
            index,
            name: None,
            file_offset: segment.file_offset,
            file_size: segment.file_size,
            virtual_address: segment.virtual_address,
            virtual_size: segment.memory_size,
            readable: Some(segment.flags & 4 != 0),
            writable: Some(segment.flags & 2 != 0),
            executable: segment.flags & 1 != 0,
            format_details: FormatDetails::Elf {
                flags: segment.flags,
                alignment: segment.alignment,
            },
        })
        .collect::<Vec<_>>();
    let executable_ranges = file_backed_executable_ranges(&segments);
    let mut limitations = vec![
        "ELF section names are unavailable because mapping is based on program headers".into(),
        "ELF load segment virtual ranges may include zero-fill tails; those tails have no file bytes".into(),
        "The image base is a file-image coordinate; runtime load bias and relocation state are unknown".into(),
    ];
    append_executable_range_limitations(&executable_ranges, &mut limitations);

    Ok(NormalizedImage {
        format: ImageFormat::Elf,
        architecture: u64::from(image.machine().0),
        // ELF program headers establish file-image coordinates, but they do
        // not establish a runtime load bias for a relocated or
        // position-independent image. Keep the base unknown rather than
        // presenting the lowest PT_LOAD address as a runtime fact.
        image_base: None,
        segments,
        executable_ranges,
        limitations,
    })
}

fn map_pe(bytes: &[u8]) -> Result<NormalizedImage, Error> {
    let image =
        super::pe_image::PeImage::parse(bytes).map_err(|error| Error::Pe(error.to_string()))?;
    let segments = image
        .sections()
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, section)| NormalizedSegment {
            index,
            name: decode_section_name(&section.name),
            file_offset: u64::from(section.file_offset),
            file_size: u64::from(section.file_size),
            virtual_address: image
                .image_base()
                .checked_add(u64::from(section.virtual_address))
                .unwrap_or(u64::MAX),
            virtual_size: u64::from(section_virtual_extent(&section)),
            readable: Some(section.permissions.readable),
            writable: Some(section.permissions.writable),
            executable: section.permissions.executable,
            format_details: FormatDetails::Pe {
                characteristics: section.characteristics,
                section_name: section.name,
            },
        })
        .collect::<Vec<_>>();
    let executable_ranges = file_backed_executable_ranges(&segments);

    let mut limitations = vec![
        "PE section virtual ranges include zero-fill tails; those tails have no file bytes".into(),
        "Addresses are image virtual addresses; relocation state is unknown".into(),
    ];
    append_executable_range_limitations(&executable_ranges, &mut limitations);

    Ok(NormalizedImage {
        format: ImageFormat::Pe,
        architecture: u64::from(image.machine().0),
        image_base: Some(image.image_base()),
        segments,
        executable_ranges,
        limitations,
    })
}

fn section_virtual_extent(section: &super::pe_image::Section) -> u32 {
    if section.virtual_size == 0 {
        section.file_size
    } else {
        section.virtual_size
    }
}

/// Return executable virtual ranges that are backed by bytes in the capture.
///
/// A segment or section can expose a larger virtual extent than its file
/// extent because the loader supplies a zero-filled tail.  The TypeScript
/// image scanner excludes that tail when validating captured method targets;
/// keeping the same boundary here prevents a file-backed lookup from being
/// treated as proven merely because its virtual address lies in zero-fill.
fn file_backed_executable_ranges(segments: &[NormalizedSegment]) -> Vec<AddressRange> {
    segments
        .iter()
        .filter(|segment| segment.executable)
        .filter_map(|segment| {
            let backed_size = segment.file_size.min(segment.virtual_size);
            let end = segment.virtual_address.checked_add(backed_size)?;
            (segment.virtual_address < end).then_some(AddressRange {
                start: segment.virtual_address,
                end,
            })
        })
        .collect()
}

fn decode_section_name(name: &[u8; 8]) -> Option<String> {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    (!name[..end].is_empty()).then(|| String::from_utf8_lossy(&name[..end]).into_owned())
}

fn is_macho_magic(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe])
            | Some([0xbe, 0xba, 0xfe, 0xca])
            | Some([0xca, 0xfe, 0xba, 0xbf])
            | Some([0xbf, 0xba, 0xfe, 0xca])
    )
}

/// Preserve every executable range while making overlapping ownership explicit.
///
/// The TypeScript mapping boundary refuses to select one file mapping when a
/// virtual address belongs to multiple candidates.  This normalized image
/// keeps the candidate ranges available to callers, and records the same
/// uncertainty for consumers that only inspect the report limitations.
fn append_executable_range_limitations(ranges: &[AddressRange], limitations: &mut Vec<String>) {
    let mut ordered = ranges.to_vec();
    ordered.sort_by_key(|range| (range.start, range.end));

    let mut previous_end = None;
    for range in ordered {
        if previous_end.is_some_and(|end| range.start < end) {
            limitations.push(
                "Executable virtual ranges overlap; ownership in the overlap is ambiguous".into(),
            );
            return;
        }

        previous_end = Some(previous_end.unwrap_or(range.end).max(range.end));
    }
}
