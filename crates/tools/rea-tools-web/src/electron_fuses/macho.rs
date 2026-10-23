//! Bounded Mach-O container identification for fuse slicing.
//!
//! Compatibility owners: `src/artifacts/apple/MachoLoadCommandReader.ts`
//! (`hasMachoMagic`, `readMachoImage`, `readSlice`, `decodeCommands`,
//! `architectureName`) and `src/domain/apple/machoContainer.ts`
//! (`readFatContainerHeader`, `classifyFatContainerIdentity`,
//! `readFatSliceDeclarations`, `inspectFatSliceRange`,
//! `validateFatSliceIdentity`). Only the facts the fuse reader consumes are
//! produced: per-slice file range and architecture; every malformed/unsupported
//! classification the TS reader would raise is preserved so error projection
//! matches.
use super::jvm_class::is_jvm_class_file;
use super::reader::FuseFormatFailure;

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM: u32 = 0xcefa_edfe;
const MH_CIGAM_64: u32 = 0xcffa_edfe;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM: u32 = 0xbeba_feca;
const FAT_CIGAM_64: u32 = 0xbfba_feca;

const MAX_LOAD_COMMAND_BYTES: usize = 16 * 1024 * 1024;
const MAX_FAT_ARCHITECTURES: u32 = 128;

const KNOWN_MACHO_CPU_TYPES: [u32; 7] = [
    7,
    0x0100_0007,
    12,
    0x0100_000c,
    0x0200_000c,
    18,
    0x0100_0012,
];
const MACHO_HEADER_MAGICS: [u32; 4] = [MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64];

const CPU_ARCH_ABI64: u32 = 0x0100_0000;
const CPU_ARCH_ABI64_32: u32 = 0x0200_0000;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;
const CPU_SUBTYPE_CAPABILITY_MASK: u32 = 0xff00_0000;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const CPU_SUBTYPE_ARM64E_X1: u32 = 12;
const CPU_SUBTYPE_X86_64_H: u32 = 8;

/// One resolved fuse slice range.
pub struct SliceRange {
    pub offset: usize,
    pub size: usize,
    pub architecture: Option<String>,
}

/// Mach-O container decode outcome for the fuse reader.
pub struct MachoContainer {
    pub universal: bool,
    pub slices: Vec<SliceRange>,
}

/// Report whether the first bytes carry a Mach-O or FAT magic number.
pub fn has_macho_magic(head: &[u8]) -> bool {
    if head.len() < 4 {
        return false;
    }
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    matches!(
        magic,
        MH_MAGIC
            | MH_MAGIC_64
            | MH_CIGAM
            | MH_CIGAM_64
            | FAT_MAGIC
            | FAT_MAGIC_64
            | FAT_CIGAM
            | FAT_CIGAM_64
    )
}

fn is_fat_magic(magic: u32) -> bool {
    matches!(magic, FAT_MAGIC | FAT_MAGIC_64 | FAT_CIGAM | FAT_CIGAM_64)
}

fn malformed(message: impl Into<String>) -> FuseFormatFailure {
    FuseFormatFailure::malformed(message)
}

fn unsupported(message: impl Into<String>) -> FuseFormatFailure {
    FuseFormatFailure::unsupported(message)
}

/// Decode a Mach-O/FAT container, returning `None` for a "not-mach-o" classification.
///
/// Port of `readMachoImage` restricted to the facts the fuse reader observes,
/// plus `identifyMacho`'s overlap check.
pub fn identify(bytes: &[u8], path: &str) -> Result<Option<MachoContainer>, FuseFormatFailure> {
    let size = bytes.len();
    if size < 8 {
        // A recognized magic with no room for a header is a truncated image.
        if has_macho_magic(bytes) {
            return Err(malformed("Mach-O header is truncated"));
        }
        return Ok(None);
    }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if is_fat_magic(magic) {
        return identify_fat(bytes, size, magic);
    }
    if magic == MH_CIGAM || magic == MH_CIGAM_64 {
        let slice = read_slice(bytes, 0, size, None)?;
        let slices = vec![slice];
        assert_non_overlapping(&slices, path)?;
        return Ok(Some(MachoContainer {
            universal: false,
            slices,
        }));
    }
    if magic == MH_MAGIC || magic == MH_MAGIC_64 {
        return Err(unsupported("big-endian Mach-O images are not supported"));
    }
    Ok(None)
}

struct FatSliceDeclaration {
    index: usize,
    offset: usize,
    size: usize,
    alignment_exponent: u32,
    cpu_type: u32,
    cpu_subtype: u32,
}

struct FatRangeIssue {
    unsupported: bool,
    reason: String,
}

fn identify_fat(
    bytes: &[u8],
    size: usize,
    magic: u32,
) -> Result<Option<MachoContainer>, FuseFormatFailure> {
    let little_endian = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
    let wide = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    let read_u32 = |offset: usize| -> u32 {
        let raw = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        if little_endian {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        }
    };
    // `readFatContainerHeader` checks a JVM class file only when the complete
    // file bytes are supplied: the TS `readMachoImage` passes the whole file
    // only for a 32-bit big-endian FAT magic within the 16 MiB bound.
    if magic == FAT_MAGIC && size <= MAX_LOAD_COMMAND_BYTES && is_jvm_class_file(bytes) {
        return Ok(None);
    }
    let count = read_u32(4);
    if count == 0 {
        return Err(malformed("FAT header declares no architectures"));
    }
    if count > MAX_FAT_ARCHITECTURES {
        return Ok(None);
    }
    let entry_size = if wide { 32 } else { 20 };
    let table_end = 8 + (count as usize) * entry_size;
    if table_end > size {
        return Ok(None);
    }
    let read_u64 = |offset: usize| -> u64 {
        let raw = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ];
        if little_endian {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        }
    };
    const MAX_SAFE: u64 = 9_007_199_254_740_991;
    let mut declarations = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let base = 8 + index * entry_size;
        let (offset, slice_size) = if wide {
            let offset = read_u64(base + 8);
            let slice_size = read_u64(base + 16);
            if offset > MAX_SAFE || slice_size > MAX_SAFE {
                return Err(malformed("FAT offset or size exceeds the safe range"));
            }
            (offset as usize, slice_size as usize)
        } else {
            (read_u32(base + 8) as usize, read_u32(base + 12) as usize)
        };
        let alignment_exponent = read_u32(base + if wide { 24 } else { 16 });
        declarations.push(FatSliceDeclaration {
            index,
            offset,
            size: slice_size,
            alignment_exponent,
            cpu_type: read_u32(base),
            cpu_subtype: read_u32(base + 4),
        });
    }
    let range_issues: Vec<Option<FatRangeIssue>> = declarations
        .iter()
        .map(|slice| inspect_fat_slice_range(slice, size, table_end))
        .collect();
    // classifyFatContainerIdentity
    let has_known_cpu = declarations
        .iter()
        .any(|slice| KNOWN_MACHO_CPU_TYPES.contains(&slice.cpu_type));
    let invalid_range = range_issues.iter().flatten().next();
    let is_mach_o = if has_known_cpu {
        if let Some(issue) = invalid_range {
            return Err(FuseFormatFailure::new(
                issue.unsupported,
                issue.reason.clone(),
            ));
        }
        true
    } else {
        // All bytes are resident; observe the header magic of each valid slice.
        let mut observed = false;
        for (index, slice) in declarations.iter().enumerate() {
            if range_issues[index].is_some() {
                continue;
            }
            if slice.offset + 4 <= size {
                let raw = [
                    bytes[slice.offset],
                    bytes[slice.offset + 1],
                    bytes[slice.offset + 2],
                    bytes[slice.offset + 3],
                ];
                let header_magic = u32::from_be_bytes(raw);
                if MACHO_HEADER_MAGICS.contains(&header_magic) {
                    observed = true;
                }
            }
        }
        if observed {
            if let Some(issue) = invalid_range {
                return Err(FuseFormatFailure::new(
                    issue.unsupported,
                    issue.reason.clone(),
                ));
            }
            true
        } else {
            false
        }
    };
    if !is_mach_o {
        return Ok(None);
    }
    // readFatSlices: parse each slice and validate its identity.
    let mut slices = Vec::with_capacity(declarations.len());
    let mut unsupported_deferred: Option<FuseFormatFailure> = None;
    for declaration in &declarations {
        let slice = match read_slice(
            bytes,
            declaration.offset,
            declaration.size,
            Some((
                declaration.index,
                declaration.cpu_type,
                declaration.cpu_subtype,
            )),
        ) {
            Ok(slice) => slice,
            Err(failure) if failure.is_unsupported() => {
                if unsupported_deferred.is_none() {
                    unsupported_deferred = Some(failure);
                }
                continue;
            }
            Err(failure) => return Err(failure),
        };
        slices.push(slice);
    }
    if let Some(failure) = unsupported_deferred {
        return Err(failure);
    }
    Ok(Some(MachoContainer {
        universal: true,
        slices,
    }))
}

fn inspect_fat_slice_range(
    declaration: &FatSliceDeclaration,
    container_size: usize,
    table_end: usize,
) -> Option<FatRangeIssue> {
    let FatSliceDeclaration {
        index,
        offset,
        size,
        alignment_exponent,
        ..
    } = *declaration;
    if size == 0 || offset < table_end {
        return Some(FatRangeIssue {
            unsupported: false,
            reason: format!("FAT architecture {index} has an invalid slice range"),
        });
    }
    if offset > container_size || size > container_size - offset {
        return Some(FatRangeIssue {
            unsupported: false,
            reason: format!("FAT architecture {index} slice range extends beyond the file"),
        });
    }
    if alignment_exponent > 52 {
        return Some(FatRangeIssue {
            unsupported: true,
            reason: format!(
                "FAT architecture {index} alignment exponent {alignment_exponent} is unsupported"
            ),
        });
    }
    if offset % (1usize << alignment_exponent) != 0 {
        return Some(FatRangeIssue {
            unsupported: false,
            reason: format!(
                "FAT architecture {index} offset is not aligned to 2^{alignment_exponent}"
            ),
        });
    }
    None
}

/// Read one thin Mach-O slice: validate its load commands and name its architecture.
///
/// Port of `readSlice` + `decodeCommands`, restricted to the fields the fuse
/// reader consumes (offset/size/architecture) while preserving the exact
/// malformed/unsupported classification.
fn read_slice(
    bytes: &[u8],
    base: usize,
    length: usize,
    fat: Option<(usize, u32, u32)>,
) -> Result<SliceRange, FuseFormatFailure> {
    let header = read_exact(bytes, base, 28, "Mach-O header")?;
    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic == MH_MAGIC_64 || magic == MH_MAGIC {
        let wide = magic == MH_MAGIC_64;
        let header_size = if wide { 32 } else { 28 };
        let read_le = |offset: usize| -> u32 {
            u32::from_le_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        };
        let command_count = read_le(16);
        let command_bytes = read_le(20) as usize;
        let cpu_type = read_le(4);
        let cpu_subtype = read_le(8);
        if command_bytes > MAX_LOAD_COMMAND_BYTES {
            return Err(unsupported(format!(
                "load commands occupy {command_bytes} bytes, above the {MAX_LOAD_COMMAND_BYTES}-byte limit"
            )));
        }
        if header_size + command_bytes > length {
            return Err(malformed("load commands extend beyond the Mach-O slice"));
        }
        let commands = read_exact(bytes, base + header_size, command_bytes, "load commands")?;
        validate_commands(commands, wide, command_count)?;
        if let Some((index, fat_cpu_type, fat_cpu_subtype)) = fat {
            if fat_cpu_type != cpu_type || fat_cpu_subtype != cpu_subtype {
                return Err(malformed(format!(
                    "FAT architecture {index} CPU type/subtype disagrees with its Mach-O header"
                )));
            }
        }
        return Ok(SliceRange {
            offset: base,
            size: length,
            architecture: Some(architecture_name(cpu_type, cpu_subtype)),
        });
    }
    if magic == swap(MH_MAGIC) || magic == swap(MH_MAGIC_64) {
        Err(unsupported("big-endian Mach-O slices are not supported"))
    } else {
        Err(malformed(format!(
            "slice at offset {base} has no Mach-O header"
        )))
    }
}

/// Walk the load commands exactly as `decodeCommands` does, raising the same
/// malformed classifications. The decoded values are not retained.
fn validate_commands(
    bytes: &[u8],
    wide: bool,
    command_count: u32,
) -> Result<(), FuseFormatFailure> {
    let alignment = if wide { 8 } else { 4 };
    let mut offset = 0usize;
    for index in 0..command_count as usize {
        if offset + 8 > bytes.len() {
            return Err(malformed(format!(
                "load command {index} starts beyond sizeofcmds"
            )));
        }
        let size = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;
        if size < 8 || size % alignment != 0 || offset + size > bytes.len() {
            return Err(malformed(format!(
                "load command {index} at offset {offset} has invalid cmdsize {size}"
            )));
        }
        offset += size;
    }
    if offset != bytes.len() {
        return Err(malformed(format!(
            "load commands declare {command_count} commands but sizeofcmds holds {} bytes",
            bytes.len()
        )));
    }
    Ok(())
}

fn assert_non_overlapping(slices: &[SliceRange], _path: &str) -> Result<(), FuseFormatFailure> {
    let mut ordered: Vec<(usize, usize, usize)> = slices
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.offset, s.size))
        .collect();
    ordered.sort_by_key(|entry| entry.1);
    for window in ordered.windows(2) {
        let (prev_index, prev_offset, prev_size) = window[0];
        let (cur_index, cur_offset, _) = window[1];
        if cur_offset < prev_offset + prev_size {
            return Err(malformed(format!(
                "Mach-O slices {prev_index} and {cur_index} overlap."
            )));
        }
    }
    Ok(())
}

fn read_exact<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    label: &str,
) -> Result<&'a [u8], FuseFormatFailure> {
    bytes
        .get(offset..offset + length)
        .ok_or_else(|| malformed(format!("{label} is truncated")))
}

fn macho_cpu_subtype_base(cpu_subtype: u32) -> u32 {
    cpu_subtype & !CPU_SUBTYPE_CAPABILITY_MASK
}

/// Port of `architectureName`.
fn architecture_name(cpu_type: u32, cpu_subtype: u32) -> String {
    let subtype = macho_cpu_subtype_base(cpu_subtype);
    if cpu_type == (CPU_TYPE_ARM | CPU_ARCH_ABI64) {
        return if subtype == CPU_SUBTYPE_ARM64E || subtype == CPU_SUBTYPE_ARM64E_X1 {
            "arm64e".to_owned()
        } else {
            "arm64".to_owned()
        };
    }
    if cpu_type == (CPU_TYPE_ARM | CPU_ARCH_ABI64_32) {
        return "arm64_32".to_owned();
    }
    if cpu_type == (CPU_TYPE_X86 | CPU_ARCH_ABI64) {
        return if subtype == CPU_SUBTYPE_X86_64_H {
            "x86_64h".to_owned()
        } else {
            "x86_64".to_owned()
        };
    }
    if cpu_type == CPU_TYPE_X86 {
        return "i386".to_owned();
    }
    if cpu_type == CPU_TYPE_ARM {
        return "arm".to_owned();
    }
    format!("cpu-{cpu_type:x}")
}

fn swap(value: u32) -> u32 {
    value.swap_bytes()
}
