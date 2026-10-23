//! Read-only Go build-info discovery in ELF, PE and thin Mach-O containers.
//!
//! Container ownership supplies validated file mappings and search ranges;
//! this module owns Go's header, string and module-framing semantics.

use crate::{base64, container, go};
use serde::Serialize;
use std::{collections::HashSet, fmt, ops::Range};

const HEADER_MAGIC: &[u8] = b"\xff Go buildinf:";
const MODULE_START: &[u8; 16] = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6";
const MODULE_END: &[u8; 16] = b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2";
const MAX_BUILD_INFO_BYTES: usize = 1024 * 1024;
const MAX_HEADER_SEARCH_BYTES: usize = 256 * 1024 * 1024;
const MAX_STRUCTURE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    Resource { stage: &'static str, maximum: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) | Self::Unsupported(reason) => formatter.write_str(reason),
            Self::Resource { stage, maximum } => {
                write!(formatter, "{stage} exceeds {maximum} bytes")
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Inline,
    Pointer,
}

#[derive(Debug, Serialize)]
pub struct SourceRange {
    pub offset: usize,
    pub bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct BuildInfo {
    pub header_offset: usize,
    pub encoding: Encoding,
    pub go_version: Option<String>,
    pub go_version_bytes_base64: String,
    pub module_text: Option<String>,
    pub module_bytes_base64: String,
    pub version_location: SourceRange,
    pub module_location: SourceRange,
    pub module: go::module::Metadata,
}

#[derive(Debug, Serialize)]
pub struct Image {
    pub format: container::Format,
    pub architecture: String,
    pub bits: u8,
    pub byte_order: container::ByteOrder,
    pub build_info: Option<BuildInfo>,
}

struct LocatedString<'a> {
    bytes: &'a [u8],
    location: SourceRange,
}

/// Inspect bounded native bytes without loading or executing the target.
pub fn read(bytes: &[u8]) -> Result<Image, Error> {
    let native = container::read(bytes).map_err(Error::from)?;
    let header = find_build_info_header(bytes, &native)?;
    let build_info = header
        .map(|header_offset| read_build_info(bytes, &native, header_offset))
        .transpose()?;

    Ok(Image {
        format: native.format,
        architecture: native.architecture,
        bits: native.bits,
        byte_order: native.byte_order,
        build_info,
    })
}

impl From<container::Error> for Error {
    fn from(error: container::Error) -> Self {
        match error {
            container::Error::Malformed(reason) => Self::Malformed(reason),
            container::Error::Unsupported(reason) => Self::Unsupported(reason),
            container::Error::StructureLimit => Self::Resource {
                stage: "structure",
                maximum: MAX_STRUCTURE_BYTES,
            },
        }
    }
}

fn find_build_info_header(
    bytes: &[u8],
    native: &container::Container,
) -> Result<Option<usize>, Error> {
    let mut seen = HashSet::new();
    let mut remaining = MAX_HEADER_SEARCH_BYTES;

    for mapping in &native.build_info_search {
        let search_bytes = mapping.span.len();
        let identity = (mapping.span.start, search_bytes, mapping.address % 16);
        if !seen.insert(identity) {
            continue;
        }
        if search_bytes > remaining {
            return Err(Error::Resource {
                stage: "Go build-info header search",
                maximum: MAX_HEADER_SEARCH_BYTES,
            });
        }
        remaining -= search_bytes;

        if let Some(header) = find_header_in_mapping(bytes, mapping)? {
            let address = mapping
                .address
                .checked_add((header - mapping.span.start) as u64)
                .ok_or(Error::Malformed(
                    "Go build-info header address exceeds its native mapping",
                ))?;
            verify_mapping(native, address, header, 32)?;
            return Ok(Some(header));
        }
    }

    Ok(None)
}

fn find_header_in_mapping(
    bytes: &[u8],
    mapping: &container::Mapping,
) -> Result<Option<usize>, Error> {
    if mapping.span.is_empty() {
        return Ok(None);
    }

    let region = bytes.get(mapping.span.clone()).ok_or(Error::Malformed(
        "Go build-info search range is outside the file",
    ))?;
    let first_aligned = ((16 - mapping.address % 16) % 16) as usize;
    let mut cursor = first_aligned;

    while cursor < region.len() {
        let Some(relative) = memchr::memmem::find(&region[cursor..], HEADER_MAGIC) else {
            return Ok(None);
        };
        let relative = cursor + relative;
        let candidate = mapping.span.start + relative;
        let address = mapping
            .address
            .checked_add(relative as u64)
            .ok_or(Error::Malformed(
                "Go build-info header address exceeds its native mapping",
            ))?;
        if address % 16 == 0 {
            if region.len() - relative < 32 {
                return Err(Error::Malformed("Go build-info header is truncated"));
            }
            return Ok(Some(candidate));
        }
        cursor = relative + 1;
    }

    Ok(None)
}

fn read_build_info(
    bytes: &[u8],
    native: &container::Container,
    header: usize,
) -> Result<BuildInfo, Error> {
    let little = matches!(native.byte_order, container::ByteOrder::Little);
    let reader = container::Reader { bytes, little };
    let ptr_size = bytes[header + 14];
    let flags = bytes[header + 15];

    if flags & !3 != 0 {
        return Err(Error::Unsupported(
            "Go build-info flags contain an unsupported format bit",
        ));
    }
    if flags & 2 == 0 && (flags & 1 != 0) == little {
        return Err(Error::Malformed(
            "Go build-info byte order disagrees with the image",
        ));
    }

    let encoding = if flags & 2 != 0 {
        Encoding::Inline
    } else {
        Encoding::Pointer
    };
    let (version, module) = match encoding {
        Encoding::Inline => read_inline_strings(&reader, native, header)?,
        Encoding::Pointer => read_pointer_strings(&reader, native, header, ptr_size)?,
    };

    let aggregate_bytes = version.bytes.len() + module.bytes.len();
    if aggregate_bytes > MAX_BUILD_INFO_BYTES {
        return Err(Error::Resource {
            stage: "Go build-info strings",
            maximum: MAX_BUILD_INFO_BYTES,
        });
    }
    if version.bytes.is_empty() {
        return Err(Error::Malformed("Go build-info compiler version is empty"));
    }

    let (go_version, module_text) = decode_build_info_text(version.bytes, module.bytes)?;
    let module_metadata = go::module::parse(module_body(module.bytes));
    Ok(BuildInfo {
        header_offset: header,
        encoding,
        go_version,
        go_version_bytes_base64: base64::encode(version.bytes),
        module_text,
        module_bytes_base64: base64::encode(module.bytes),
        version_location: version.location,
        module_location: module.location,
        module: module_metadata,
    })
}

fn module_body(bytes: &[u8]) -> &[u8] {
    if bytes.is_empty() {
        return bytes;
    }

    &bytes[16..bytes.len() - 16]
}

fn read_inline_strings<'a>(
    reader: &container::Reader<'a>,
    native: &container::Container,
    header: usize,
) -> Result<(LocatedString<'a>, LocatedString<'a>), Error> {
    let end = native
        .build_info_search
        .iter()
        .find(|mapping| mapping.span.contains(&header))
        .map(|mapping| mapping.span.end)
        .ok_or(Error::Malformed(
            "Go build-info header is outside its search mapping",
        ))?;
    let first_string = header
        .checked_add(32)
        .ok_or(Error::Malformed("Go build-info string offset overflows"))?;
    let version = read_inline_string(reader, first_string, end.saturating_sub(first_string))?;
    let next_string = version
        .location
        .offset
        .checked_add(version.location.bytes)
        .ok_or(Error::Malformed("Go build-info string range overflows"))?;
    let module = read_inline_string(reader, next_string, end.saturating_sub(next_string))?;
    let whole_length = module
        .location
        .offset
        .checked_add(module.location.bytes)
        .and_then(|limit| limit.checked_sub(header))
        .ok_or(Error::Malformed("Go build-info string range overflows"))?;
    let address = native
        .build_info_search
        .iter()
        .find(|mapping| mapping.span.contains(&header))
        .and_then(|mapping| {
            mapping
                .address
                .checked_add((header - mapping.span.start) as u64)
        })
        .ok_or(Error::Malformed("Go build-info header is not mapped"))?;
    verify_mapping(native, address, header, whole_length)?;

    Ok((version, module))
}

fn read_inline_string<'a>(
    reader: &container::Reader<'a>,
    offset: usize,
    remaining: usize,
) -> Result<LocatedString<'a>, Error> {
    let mut length = 0_u64;

    for index in 0..10 {
        if index >= remaining {
            return Err(Error::Malformed("Go build-info varint is truncated"));
        }
        let byte = *reader
            .bytes
            .get(offset + index)
            .ok_or(Error::Malformed("Go build-info varint is truncated"))?;
        if index == 9 && byte > 1 {
            return Err(Error::Malformed("Go build-info varint overflows 64 bits"));
        }

        length |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            let length = usize::try_from(length).map_err(|_| Error::Resource {
                stage: "Go build-info string",
                maximum: MAX_BUILD_INFO_BYTES,
            })?;
            if length > MAX_BUILD_INFO_BYTES {
                return Err(Error::Resource {
                    stage: "Go build-info string",
                    maximum: MAX_BUILD_INFO_BYTES,
                });
            }
            let header_bytes = index + 1;
            if length > remaining.saturating_sub(header_bytes) {
                return Err(Error::Malformed("Go build-info string range is truncated"));
            }
            let start = offset
                .checked_add(header_bytes)
                .ok_or(Error::Malformed("Go build-info string offset overflows"))?;
            let range = start..start + length;
            let bytes = reader
                .bytes
                .get(range.clone())
                .ok_or(Error::Malformed("Go build-info string range is truncated"))?;
            return Ok(LocatedString {
                bytes,
                location: SourceRange {
                    offset: range.start,
                    bytes: length,
                },
            });
        }
    }

    Err(Error::Malformed("Go build-info varint is unterminated"))
}

fn read_pointer_strings<'a>(
    reader: &container::Reader<'a>,
    native: &container::Container,
    header: usize,
    ptr_size: u8,
) -> Result<(LocatedString<'a>, LocatedString<'a>), Error> {
    if ptr_size != 4 && ptr_size != 8 {
        return Err(Error::Malformed(
            "Go build-info pointer width must be 4 or 8",
        ));
    }
    if ptr_size * 8 != native.bits {
        return Err(Error::Malformed(
            "Go build-info pointer width disagrees with the image",
        ));
    }

    let bits = native.bits;
    let pointer_start = header
        .checked_add(16)
        .ok_or(Error::Malformed("Go build-info pointer field overflows"))?;
    let version_address = reader.word(pointer_start, bits)?;
    let module_pointer = pointer_start
        .checked_add(usize::from(ptr_size))
        .ok_or(Error::Malformed("Go build-info pointer field overflows"))?;
    let module_address = reader.word(module_pointer, bits)?;
    let version = read_pointer_string(reader, native, version_address)?;
    let module = read_optional_module_string(reader, native, module_address, module_pointer)?;
    Ok((version, module))
}

fn read_pointer_string<'a>(
    reader: &container::Reader<'a>,
    native: &container::Container,
    address: u64,
) -> Result<LocatedString<'a>, Error> {
    let width = usize::from(native.bits / 8);
    let pointer_fields = width
        .checked_mul(2)
        .ok_or(Error::Malformed("Go build-info string header overflows"))?;
    let header_offset = container::mapped_offset(
        &native.mappings,
        &native.zero_fills,
        address,
        pointer_fields,
    )?;
    let data_address = reader.word(header_offset, native.bits)?;
    let length = reader.word(header_offset + width, native.bits)?;
    let length = usize::try_from(length).map_err(|_| Error::Resource {
        stage: "Go build-info pointer string",
        maximum: MAX_BUILD_INFO_BYTES,
    })?;
    if length > MAX_BUILD_INFO_BYTES {
        return Err(Error::Resource {
            stage: "Go build-info pointer string",
            maximum: MAX_BUILD_INFO_BYTES,
        });
    }

    let data_offset = if length == 0 && data_address == 0 {
        header_offset
    } else {
        container::mapped_offset(&native.mappings, &native.zero_fills, data_address, length)?
    };
    let range = checked_range(reader.bytes, data_offset, length)?;
    Ok(LocatedString {
        bytes: &reader.bytes[range.clone()],
        location: SourceRange {
            offset: range.start,
            bytes: length,
        },
    })
}

fn read_optional_module_string<'a>(
    reader: &container::Reader<'a>,
    native: &container::Container,
    address: u64,
    pointer_field: usize,
) -> Result<LocatedString<'a>, Error> {
    let width = usize::from(native.bits / 8);
    let header_size = width
        .checked_mul(2)
        .ok_or(Error::Malformed("Go module pointer header overflows"))?;
    if is_zero_filled_span(native, address, header_size)? {
        return Ok(LocatedString {
            bytes: &reader.bytes[..0],
            location: SourceRange {
                offset: pointer_field,
                bytes: 0,
            },
        });
    }
    read_pointer_string(reader, native, address)
}

fn verify_mapping(
    native: &container::Container,
    address: u64,
    expected_offset: usize,
    size: usize,
) -> Result<(), Error> {
    if container::mapped_offset(&native.mappings, &native.zero_fills, address, size)?
        != expected_offset
    {
        return Err(Error::Malformed(
            "Go build-info bytes disagree with their virtual mapping",
        ));
    }
    Ok(())
}

fn is_zero_filled_span(
    native: &container::Container,
    address: u64,
    size: usize,
) -> Result<bool, Error> {
    let start = u128::from(address);
    let end = start + size as u128;
    let fully_zero_filled = native
        .zero_fills
        .iter()
        .any(|zero| start >= zero.address && end <= zero.address.saturating_add(zero.size));
    if !fully_zero_filled {
        return Ok(false);
    }

    for mapping in &native.mappings {
        let mapping_start = u128::from(mapping.address);
        let mapping_end = mapping_start + mapping.span.len() as u128;
        if start < mapping_end && mapping_start < end {
            return Err(Error::Malformed(
                "Go build-info pointer aliases file-backed and zero-fill memory",
            ));
        }
    }
    Ok(true)
}

fn decode_build_info_text(
    version: &[u8],
    module: &[u8],
) -> Result<(Option<String>, Option<String>), Error> {
    let go_version = std::str::from_utf8(version).ok().map(str::to_owned);
    if module.is_empty() {
        return Ok((go_version, Some(String::new())));
    }
    if module.len() < 33
        || &module[..16] != MODULE_START
        || &module[module.len() - 16..] != MODULE_END
        || module[module.len() - 17] != b'\n'
    {
        return Err(Error::Malformed("Go module string framing is invalid"));
    }
    let module_text = std::str::from_utf8(&module[16..module.len() - 16])
        .ok()
        .map(str::to_owned);
    Ok((go_version, module_text))
}

fn checked_range(bytes: &[u8], offset: usize, size: usize) -> Result<Range<usize>, Error> {
    let end = offset
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or(Error::Malformed(
            "Go build-info string range is truncated or outside the file",
        ))?;
    Ok(offset..end)
}
