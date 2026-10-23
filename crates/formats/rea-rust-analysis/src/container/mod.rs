//! One bounded interpretation of native headers for the static Rust reader.
//! Retain only the selected dependency section and read-only scan ranges.

mod elf;
mod macho;
mod pe;

pub(crate) use pe::{PeFormat, ResourceLayout, read_resource_layout};

use serde::Serialize;
use std::{fmt, ops::Range};

const MAX_STRUCTURE: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    StructureLimit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) | Self::Unsupported(reason) => f.write_str(reason),
            Self::StructureLimit => {
                f.write_str("native structure exceeds the 16 MiB decoding budget")
            }
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Elf,
    Pe,
    Macho,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteOrder {
    Little,
    Big,
}

pub struct Container {
    pub format: Format,
    pub architecture: String,
    pub bits: u8,
    pub byte_order: ByteOrder,
    pub dependency: Option<Range<usize>>,
    pub read_only: Vec<Range<usize>>,
    pub mappings: Vec<Mapping>,
    pub zero_fills: Vec<ZeroFill>,
    pub build_info_search: Vec<Mapping>,
}

pub(super) struct ImageLayout {
    pub format: Format,
    pub architecture: String,
    pub bits: u8,
    pub little_endian: bool,
    pub mappings: Vec<Mapping>,
    pub zero_fills: Vec<ZeroFill>,
    pub build_info_search: Vec<Mapping>,
}

#[derive(Default)]
struct Sections {
    dependency_count: usize,
    dependency: Option<Range<usize>>,
    dependency_compressed: bool,
    read_only: Vec<Range<usize>>,
}

impl Sections {
    fn observe(
        &mut self,
        span: Option<Range<usize>>,
        dependency: bool,
        read_only: bool,
        compressed: bool,
    ) {
        if dependency {
            self.dependency_count += 1;
            if self.dependency_count == 1 {
                self.dependency = span.clone();
                self.dependency_compressed = compressed;
            }
        }
        if read_only && let Some(span) = span {
            self.read_only.push(span);
        }
    }

    fn finish(mut self, layout: ImageLayout) -> Result<Container, Error> {
        if self.dependency_count > 1 {
            return Err(Error::Malformed(
                "image contains more than one dependency section",
            ));
        }
        if self.dependency_count == 1 {
            if self.dependency_compressed {
                return Err(Error::Unsupported(
                    "compressed native dependency sections are unsupported",
                ));
            }
            if self.dependency.is_none() {
                return Err(Error::Malformed("dependency section is not file-backed"));
            }
        }
        self.read_only.sort_unstable_by_key(|span| span.start);
        // Merge in place: overlapping/duplicate section declarations are scanned
        // once, without retaining a second range inventory.
        let mut length = 0;
        for index in 0..self.read_only.len() {
            let span = self.read_only[index].clone();
            if length > 0 && span.start <= self.read_only[length - 1].end {
                self.read_only[length - 1].end = self.read_only[length - 1].end.max(span.end);
            } else {
                self.read_only[length] = span;
                length += 1;
            }
        }
        self.read_only.truncate(length);
        Ok(Container {
            format: layout.format,
            architecture: layout.architecture,
            bits: layout.bits,
            byte_order: if layout.little_endian {
                ByteOrder::Little
            } else {
                ByteOrder::Big
            },
            dependency: self.dependency,
            read_only: self.read_only,
            mappings: layout.mappings,
            zero_fills: layout.zero_fills,
            build_info_search: layout.build_info_search,
        })
    }
}

pub(super) struct Reader<'a> {
    pub bytes: &'a [u8],
    pub little: bool,
}
impl<'a> Reader<'a> {
    pub(super) fn range(&self, offset: u64, size: u64) -> Result<Range<usize>, Error> {
        let length = self.bytes.len() as u64;
        if offset > length || size > length - offset {
            return Err(Error::Malformed(
                "native range is truncated or outside the file",
            ));
        }
        Ok(offset as usize..(offset + size) as usize)
    }
    fn array<const N: usize>(&self, offset: usize) -> Result<[u8; N], Error> {
        self.bytes[self.range(offset as u64, N as u64)?]
            .try_into()
            .map_err(|_| Error::Malformed("native numeric field is truncated"))
    }
    pub(super) fn u16(&self, offset: usize) -> Result<u16, Error> {
        let bytes = self.array(offset)?;
        Ok(if self.little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }
    pub(super) fn u32(&self, offset: usize) -> Result<u32, Error> {
        let bytes = self.array(offset)?;
        Ok(if self.little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }
    pub(super) fn word(&self, offset: usize, bits: u8) -> Result<u64, Error> {
        if bits == 32 {
            return self.u32(offset).map(u64::from);
        }
        let bytes = self.array(offset)?;
        Ok(if self.little {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }
    fn table(&self, offset: u64, count: u64, width: u64) -> Result<usize, Error> {
        let size = count
            .checked_mul(width)
            .filter(|size| *size <= MAX_STRUCTURE)
            .ok_or(Error::StructureLimit)?;
        Ok(self.range(offset, size)?.start)
    }
    fn declared(&self, offset: u64, size: u64) -> Option<Range<usize>> {
        if size == 0 {
            None
        } else {
            self.range(offset, size).ok()
        }
    }
    fn fixed_name(&self, offset: usize, size: usize) -> Result<&'a [u8], Error> {
        let bytes = &self.bytes[self.range(offset as u64, size as u64)?];
        Ok(&bytes[..bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len())])
    }
}

#[derive(Clone)]
pub(super) struct Mapping {
    pub address: u64,
    pub span: Range<usize>,
}
pub(super) struct ZeroFill {
    pub address: u128,
    pub size: u128,
}

pub(super) fn mapped_offset(
    mappings: &[Mapping],
    zero_fills: &[ZeroFill],
    address: u64,
    size: usize,
) -> Result<usize, Error> {
    let address = u128::from(address);
    let end = address + size as u128;
    let mut found = None;
    for mapping in mappings {
        let base = u128::from(mapping.address);
        if address < base
            || address - base > mapping.span.len() as u128
            || size as u128 > mapping.span.len() as u128 - (address - base)
        {
            continue;
        }
        let offset = mapping.span.start + (address - base) as usize;
        if found.is_some_and(|previous| previous != offset) {
            return Err(Error::Malformed(
                "virtual address has ambiguous file mappings",
            ));
        }
        found = Some(offset);
    }
    let found = found.ok_or(Error::Malformed("virtual span is not file mapped"))?;
    for zero in zero_fills {
        if size > 0 && zero.size > 0 && address < zero.address + zero.size && zero.address < end {
            return Err(Error::Malformed(
                "virtual span aliases file and zero-fill memory",
            ));
        }
    }
    for mapping in mappings {
        let base = u128::from(mapping.address);
        let start = address.max(base);
        let overlap_end = end.min(base + mapping.span.len() as u128);
        if start < overlap_end
            && found as u128 + start - address != mapping.span.start as u128 + start - base
        {
            return Err(Error::Malformed(
                "virtual address has ambiguous file mappings",
            ));
        }
    }
    Ok(found)
}

pub fn read(bytes: &[u8]) -> Result<Container, Error> {
    if bytes.starts_with(b"\x7fELF") {
        return elf::read(bytes);
    }
    if bytes.starts_with(b"MZ") {
        return pe::read(bytes);
    }
    if let Some(prefix) = bytes.get(..4) {
        let magic = u32::from_be_bytes(
            prefix
                .try_into()
                .map_err(|_| Error::Malformed("truncated magic"))?,
        );
        if matches!(magic, 0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe) {
            return macho::read(bytes, magic);
        }
        if matches!(magic, 0xcafebabe | 0xcafebabf | 0xbebafeca | 0xbfbafeca) {
            let reader = Reader {
                bytes,
                little: matches!(magic, 0xbebafeca | 0xbfbafeca),
            };
            let count = reader.u32(4)?;
            if count == 0 {
                return Err(Error::Malformed("FAT header declares no architectures"));
            }
            let wide = matches!(magic, 0xcafebabf | 0xbfbafeca);
            let width = if wide { 32 } else { 20 };
            if count <= 128 && 8 + u64::from(count) * width <= bytes.len() as u64 && wide {
                for index in 0..count as usize {
                    let entry = 8 + index * width as usize;
                    if reader.word(entry + 8, 64)? > 9_007_199_254_740_991
                        || reader.word(entry + 16, 64)? > 9_007_199_254_740_991
                    {
                        return Err(Error::Malformed(
                            "FAT offset or size exceeds the safe range",
                        ));
                    }
                }
            }
        }
    }
    Err(Error::Unsupported(
        "Only ELF, PE, and thin Mach-O native images are supported",
    ))
}
