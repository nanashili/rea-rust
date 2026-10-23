//! Bounded parsing of universal (fat) Mach-O containers.
//!
//! A universal image contains one or more complete thin Mach-O images.  This
//! module describes the container and its slices.  Selection is available only
//! through an explicit caller-provided identity and returns a bounded borrowed
//! view; it never ranks architectures or reinterprets a slice as a native
//! image.

use std::fmt;

const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_CIGAM: u32 = 0xbeba_feca;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM_64: u32 = 0xbfba_feca;
const MACHO_MAGIC_32_BE: u32 = 0xfeed_face;
const MACHO_MAGIC_32_LE: u32 = 0xcefa_edfe;
const MACHO_MAGIC_64_BE: u32 = 0xfeed_facf;
const MACHO_MAGIC_64_LE: u32 = 0xcffa_edfe;
// Keep this aligned with the bounded TypeScript FAT header reader.  A larger
// count is treated as outside FAT inspection coverage there, so accepting it
// here would make the native path claim structure that the shared boundary
// deliberately leaves unresolved.
const MAX_SLICES: usize = 128;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatEndian {
    Big,
    Little,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatClass {
    Fat32,
    Fat64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SliceRange {
    pub offset: u64,
    pub size: u64,
}

impl SliceRange {
    pub fn end(self) -> Option<u64> {
        self.offset.checked_add(self.size)
    }

    pub fn contains(self, offset: u64) -> bool {
        self.end()
            .is_some_and(|end| offset >= self.offset && offset < end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SliceStatus {
    Valid,
    Empty,
    OutOfBounds,
    Overflow,
    OverlapsHeader,
    UnsupportedAlignment { maximum: u32 },
    Misaligned { required: u32 },
    Overlaps { other_index: usize },
    DuplicateArchitecture { other_index: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatSlice {
    pub index: usize,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub range: SliceRange,
    pub alignment_power: u32,
    pub reserved: Option<u32>,
    pub status: Vec<SliceStatus>,
}

impl FatSlice {
    pub fn is_valid(&self) -> bool {
        self.status
            .iter()
            .all(|status| matches!(status, SliceStatus::Valid))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatImage {
    pub class: FatClass,
    pub endian: FatEndian,
    pub file_length: u64,
    pub slices: Vec<FatSlice>,
}

/// An explicit caller choice for a slice in a universal image.
///
/// Selection never ranks architectures or falls back to another slice.  The
/// index is the stable identity assigned by the FAT architecture table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatSliceSelector {
    Index(usize),
    Architecture { cpu_type: u32, cpu_subtype: u32 },
}

/// The exact architecture identity requested by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FatArchitectureRequest {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
}

/// Result of applying an optional architecture request to a FAT table.
///
/// `Unknown` is intentional when no request was supplied.  A repeated
/// architecture identity remains `Ambiguous`; table order is never used as a
/// tie breaker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FatArchitectureSelection<'a> {
    Unknown,
    Selected(FatSliceView<'a>),
    Ambiguous { indices: Vec<usize> },
    Absent { cpu_type: u32, cpu_subtype: u32 },
}

/// A validated, borrowed view of one slice and its original container range.
///
/// Keeping the `FatSlice` alongside the borrowed bytes prevents consumers from
/// losing the FAT table identity when they hand the thin bytes to another
/// parser.  The bytes are never copied or extended beyond the declared range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FatSliceView<'a> {
    pub slice: &'a FatSlice,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionError {
    IndexOutOfBounds {
        index: usize,
    },
    ArchitectureNotFound {
        cpu_type: u32,
        cpu_subtype: u32,
    },
    ArchitectureAmbiguous {
        cpu_type: u32,
        cpu_subtype: u32,
    },
    InvalidSlice {
        index: usize,
        range: SliceRange,
        status: Vec<SliceStatus>,
    },
    SourceRangeOutOfBounds {
        index: usize,
        range: SliceRange,
    },
    SliceIdentityMismatch {
        index: usize,
        expected_cpu_type: u32,
        expected_cpu_subtype: u32,
        observed_cpu_type: u32,
        observed_cpu_subtype: u32,
    },
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds { index } => {
                write!(formatter, "FAT slice index {index} is absent")
            }
            Self::ArchitectureNotFound {
                cpu_type,
                cpu_subtype,
            } => write!(
                formatter,
                "FAT architecture cputype {cpu_type} cpusubtype {cpu_subtype} is absent"
            ),
            Self::ArchitectureAmbiguous {
                cpu_type,
                cpu_subtype,
            } => write!(
                formatter,
                "FAT architecture cputype {cpu_type} cpusubtype {cpu_subtype} is ambiguous"
            ),
            Self::InvalidSlice {
                index,
                range,
                status,
            } => {
                write!(
                    formatter,
                    "FAT slice {index} at offset {} ({} bytes) is invalid: {status:?}",
                    range.offset, range.size
                )
            }
            Self::SourceRangeOutOfBounds { index, range } => {
                write!(
                    formatter,
                    "FAT slice {index} at offset {} ({} bytes) is outside the supplied bytes",
                    range.offset, range.size
                )
            }
            Self::SliceIdentityMismatch {
                index,
                expected_cpu_type,
                expected_cpu_subtype,
                observed_cpu_type,
                observed_cpu_subtype,
            } => write!(
                formatter,
                "FAT slice {index} architecture ({expected_cpu_type}, {expected_cpu_subtype}) disagrees with its Mach-O header ({observed_cpu_type}, {observed_cpu_subtype})"
            ),
        }
    }
}

impl std::error::Error for SelectionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooSmall,
    UnsupportedMagic(u32),
    NoSlices,
    SliceCountTooLarge(u32),
    SliceExtentExceedsSafeRange,
    HeaderOutOfBounds,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => formatter.write_str("universal Mach-O header is truncated"),
            Self::UnsupportedMagic(magic) => {
                write!(
                    formatter,
                    "unsupported universal Mach-O magic 0x{magic:08x}"
                )
            }
            Self::NoSlices => {
                formatter.write_str("universal Mach-O header declares no architectures")
            }
            Self::SliceCountTooLarge(count) => {
                write!(
                    formatter,
                    "universal Mach-O slice count {count} exceeds the limit"
                )
            }
            Self::SliceExtentExceedsSafeRange => {
                formatter.write_str("universal Mach-O offset or size exceeds the safe range")
            }
            Self::HeaderOutOfBounds => formatter
                .write_str("universal Mach-O architecture table exceeds the supplied bytes"),
        }
    }
}

impl std::error::Error for Error {}

impl FatImage {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 8 {
            return Err(Error::TooSmall);
        }

        let magic = u32::from_be_bytes(bytes[..4].try_into().expect("four-byte magic"));
        let (class, endian, entry_size) = match magic {
            FAT_MAGIC => (FatClass::Fat32, FatEndian::Big, 20usize),
            FAT_CIGAM => (FatClass::Fat32, FatEndian::Little, 20usize),
            FAT_MAGIC_64 => (FatClass::Fat64, FatEndian::Big, 32usize),
            FAT_CIGAM_64 => (FatClass::Fat64, FatEndian::Little, 32usize),
            other => return Err(Error::UnsupportedMagic(other)),
        };

        let slice_count = read_u32(bytes, 4, endian)?;
        if slice_count == 0 {
            return Err(Error::NoSlices);
        }
        let slice_count_usize =
            usize::try_from(slice_count).map_err(|_| Error::SliceCountTooLarge(slice_count))?;
        if slice_count_usize > MAX_SLICES {
            return Err(Error::SliceCountTooLarge(slice_count));
        }
        let table_size = entry_size
            .checked_mul(slice_count_usize)
            .ok_or(Error::HeaderOutOfBounds)?;
        let table_end = 8usize
            .checked_add(table_size)
            .ok_or(Error::HeaderOutOfBounds)?;
        if table_end > bytes.len() {
            return Err(Error::HeaderOutOfBounds);
        }

        let mut slices = Vec::with_capacity(slice_count_usize);
        for index in 0..slice_count_usize {
            let entry_offset = 8 + index * entry_size;
            let cpu_type = read_u32(bytes, entry_offset, endian)?;
            let cpu_subtype = read_u32(bytes, entry_offset + 4, endian)?;
            let (offset, size, alignment_power, reserved) = match class {
                FatClass::Fat32 => (
                    u64::from(read_u32(bytes, entry_offset + 8, endian)?),
                    u64::from(read_u32(bytes, entry_offset + 12, endian)?),
                    read_u32(bytes, entry_offset + 16, endian)?,
                    None,
                ),
                FatClass::Fat64 => {
                    let offset = read_u64(bytes, entry_offset + 8, endian)?;
                    let size = read_u64(bytes, entry_offset + 16, endian)?;
                    if offset > MAX_SAFE_INTEGER || size > MAX_SAFE_INTEGER {
                        return Err(Error::SliceExtentExceedsSafeRange);
                    }
                    (
                        offset,
                        size,
                        read_u32(bytes, entry_offset + 24, endian)?,
                        Some(read_u32(bytes, entry_offset + 28, endian)?),
                    )
                }
            };
            let range = SliceRange { offset, size };
            slices.push(FatSlice {
                index,
                cpu_type,
                cpu_subtype,
                range,
                alignment_power,
                reserved,
                status: statuses_for_slice(
                    range,
                    alignment_power,
                    table_end as u64,
                    bytes.len() as u64,
                ),
            });
        }

        add_overlap_statuses(&mut slices);
        add_duplicate_architecture_statuses(&mut slices);

        Ok(Self {
            class,
            endian,
            file_length: bytes.len() as u64,
            slices,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(bytes)
    }

    /// Borrow one valid slice using an explicit caller-selected identity.
    pub fn select_slice<'a>(
        &'a self,
        bytes: &'a [u8],
        selector: FatSliceSelector,
    ) -> Result<FatSliceView<'a>, SelectionError> {
        let slice = match selector {
            FatSliceSelector::Index(index) => self
                .slices
                .get(index)
                .ok_or(SelectionError::IndexOutOfBounds { index })?,
            FatSliceSelector::Architecture {
                cpu_type,
                cpu_subtype,
            } => {
                let mut matches = self
                    .slices
                    .iter()
                    .filter(|slice| slice.cpu_type == cpu_type && slice.cpu_subtype == cpu_subtype);
                let Some(slice) = matches.next() else {
                    return Err(SelectionError::ArchitectureNotFound {
                        cpu_type,
                        cpu_subtype,
                    });
                };
                if matches.next().is_some() {
                    return Err(SelectionError::ArchitectureAmbiguous {
                        cpu_type,
                        cpu_subtype,
                    });
                }
                slice
            }
        };

        if !slice.is_valid() {
            return Err(SelectionError::InvalidSlice {
                index: slice.index,
                range: slice.range,
                status: slice.status.clone(),
            });
        }

        let slice_bytes =
            bounded_slice(bytes, slice).ok_or(SelectionError::SourceRangeOutOfBounds {
                index: slice.index,
                range: slice.range,
            })?;

        if let Some((observed_cpu_type, observed_cpu_subtype)) = thin_macho_identity(slice_bytes) {
            if observed_cpu_type != slice.cpu_type || observed_cpu_subtype != slice.cpu_subtype {
                return Err(SelectionError::SliceIdentityMismatch {
                    index: slice.index,
                    expected_cpu_type: slice.cpu_type,
                    expected_cpu_subtype: slice.cpu_subtype,
                    observed_cpu_type,
                    observed_cpu_subtype,
                });
            }
        }

        Ok(FatSliceView {
            slice,
            bytes: slice_bytes,
        })
    }

    /// Borrow a slice by its FAT table index.
    pub fn slice_at<'a>(
        &'a self,
        bytes: &'a [u8],
        index: usize,
    ) -> Result<FatSliceView<'a>, SelectionError> {
        self.select_slice(bytes, FatSliceSelector::Index(index))
    }

    /// Extract one slice by table index, retaining its original FAT identity.
    pub fn extract_slice<'a>(
        &'a self,
        bytes: &'a [u8],
        index: usize,
    ) -> Result<FatSliceView<'a>, SelectionError> {
        self.slice_at(bytes, index)
    }

    /// Select a unique architecture record without applying compatibility
    /// ranking or silently choosing a neighboring subtype.
    pub fn select_architecture_slice<'a>(
        &'a self,
        bytes: &'a [u8],
        cpu_type: u32,
        cpu_subtype: u32,
    ) -> Result<FatSliceView<'a>, SelectionError> {
        self.select_slice(
            bytes,
            FatSliceSelector::Architecture {
                cpu_type,
                cpu_subtype,
            },
        )
    }

    /// Resolve an optional exact architecture request without guessing.
    pub fn select_requested_architecture<'a>(
        &'a self,
        bytes: &'a [u8],
        request: Option<FatArchitectureRequest>,
    ) -> Result<FatArchitectureSelection<'a>, SelectionError> {
        let Some(request) = request else {
            return Ok(FatArchitectureSelection::Unknown);
        };

        let matches = self
            .slices
            .iter()
            .filter(|slice| {
                slice.cpu_type == request.cpu_type && slice.cpu_subtype == request.cpu_subtype
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(FatArchitectureSelection::Absent {
                cpu_type: request.cpu_type,
                cpu_subtype: request.cpu_subtype,
            }),
            [_first, _second, ..] => Ok(FatArchitectureSelection::Ambiguous {
                indices: matches.iter().map(|slice| slice.index).collect(),
            }),
            [slice] => {
                let view = self.select_slice(bytes, FatSliceSelector::Index(slice.index))?;
                Ok(FatArchitectureSelection::Selected(view))
            }
        }
    }
}

fn statuses_for_slice(
    range: SliceRange,
    alignment_power: u32,
    header_end: u64,
    file_length: u64,
) -> Vec<SliceStatus> {
    let mut statuses = Vec::new();
    if range.size == 0 {
        statuses.push(SliceStatus::Empty);
    }
    let Some(end) = range.end() else {
        statuses.push(SliceStatus::Overflow);
        return statuses;
    };
    if alignment_power > 52 {
        statuses.push(SliceStatus::UnsupportedAlignment { maximum: 52 });
    } else {
        let alignment = 1u64 << alignment_power;
        if range.offset % alignment != 0 {
            statuses.push(SliceStatus::Misaligned {
                required: alignment_power,
            });
        }
    }
    if end > file_length {
        statuses.push(SliceStatus::OutOfBounds);
    }
    if range.offset < header_end && end > 0 {
        statuses.push(SliceStatus::OverlapsHeader);
    }
    if statuses.is_empty() {
        statuses.push(SliceStatus::Valid);
    }
    statuses
}

fn bounded_slice<'a>(bytes: &'a [u8], slice: &FatSlice) -> Option<&'a [u8]> {
    let start = usize::try_from(slice.range.offset).ok()?;
    let size = usize::try_from(slice.range.size).ok()?;
    let end = start.checked_add(size)?;
    bytes.get(start..end)
}

fn thin_macho_identity(bytes: &[u8]) -> Option<(u32, u32)> {
    let magic = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
    let endian = match magic {
        MACHO_MAGIC_32_BE | MACHO_MAGIC_64_BE => FatEndian::Big,
        MACHO_MAGIC_32_LE | MACHO_MAGIC_64_LE => FatEndian::Little,
        _ => return None,
    };
    Some((
        read_u32_at(bytes, 4, endian)?,
        read_u32_at(bytes, 8, endian)?,
    ))
}

fn read_u32_at(bytes: &[u8], offset: usize, endian: FatEndian) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    let value = raw.try_into().ok()?;
    Some(match endian {
        FatEndian::Big => u32::from_be_bytes(value),
        FatEndian::Little => u32::from_le_bytes(value),
    })
}

fn add_duplicate_architecture_statuses(slices: &mut [FatSlice]) {
    for left in 0..slices.len() {
        for right in left + 1..slices.len() {
            if slices[left].cpu_type == slices[right].cpu_type
                && slices[left].cpu_subtype == slices[right].cpu_subtype
            {
                slices[left]
                    .status
                    .push(SliceStatus::DuplicateArchitecture { other_index: right });
                slices[right]
                    .status
                    .push(SliceStatus::DuplicateArchitecture { other_index: left });
            }
        }
    }
}

fn add_overlap_statuses(slices: &mut [FatSlice]) {
    for left in 0..slices.len() {
        for right in left + 1..slices.len() {
            let left_range = slices[left].range;
            let right_range = slices[right].range;
            let overlaps = left_range.end().is_some_and(|left_end| {
                right_range.end().is_some_and(|right_end| {
                    left_range.offset < right_end && right_range.offset < left_end
                })
            });
            if overlaps {
                slices[left]
                    .status
                    .push(SliceStatus::Overlaps { other_index: right });
                slices[right]
                    .status
                    .push(SliceStatus::Overlaps { other_index: left });
            }
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize, endian: FatEndian) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::HeaderOutOfBounds)?;
    let raw = bytes.get(offset..end).ok_or(Error::HeaderOutOfBounds)?;
    let value = raw.try_into().expect("checked four-byte read");
    Ok(match endian {
        FatEndian::Big => u32::from_be_bytes(value),
        FatEndian::Little => u32::from_le_bytes(value),
    })
}

fn read_u64(bytes: &[u8], offset: usize, endian: FatEndian) -> Result<u64, Error> {
    let end = offset.checked_add(8).ok_or(Error::HeaderOutOfBounds)?;
    let raw = bytes.get(offset..end).ok_or(Error::HeaderOutOfBounds)?;
    let value = raw.try_into().expect("checked eight-byte read");
    Ok(match endian {
        FatEndian::Big => u64::from_be_bytes(value),
        FatEndian::Little => u64::from_le_bytes(value),
    })
}
