//! Bounded Mach-O header facts used by static dyld load-path tracing.
//!
//! This parser reads only architecture tables and load commands. It does not
//! inspect mapped code or execute the target. The application owner supplies
//! the file-size bound before calling `read_image`.

const MAX_LOAD_COMMAND_BYTES: usize = 16 * 1024 * 1024;
const MAX_FAT_ARCHITECTURES: usize = 128;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM: u32 = 0xcefa_edfe;
const MH_CIGAM_64: u32 = 0xcffa_edfe;

const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM: u32 = 0xbeba_feca;
const FAT_CIGAM_64: u32 = 0xbfba_feca;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageFacts {
    Parsed { slices: Vec<Slice> },
    Malformed { reason: String },
    Unsupported { reason: String },
    NotMachO,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Slice {
    pub architecture: String,
    pub slice_offset: u64,
    pub slice_size: u64,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub fat_cpu_type: Option<u32>,
    pub fat_cpu_subtype: Option<u32>,
    pub fat_alignment_exponent: Option<u8>,
    pub file_type: String,
    pub file_type_code: u32,
    pub platform: Option<u32>,
    pub platforms: Vec<u32>,
    pub install_name: Option<String>,
    pub dependencies: Vec<Dependency>,
    pub rpaths: Vec<String>,
    pub dyld_environment: Vec<String>,
    pub code_signature_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub command: String,
    pub encoding: String,
    pub install_name: String,
    pub weak: bool,
    pub upward: bool,
    pub reexport: bool,
    pub delayed_init: bool,
    pub current_version: String,
    pub compatibility_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssueKind {
    Malformed,
    Unsupported,
}

#[derive(Clone, Debug)]
struct ParseIssue {
    kind: IssueKind,
    reason: String,
}

impl ParseIssue {
    fn malformed(reason: impl Into<String>) -> Self {
        Self {
            kind: IssueKind::Malformed,
            reason: reason.into(),
        }
    }

    fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            kind: IssueKind::Unsupported,
            reason: reason.into(),
        }
    }

    fn into_facts(self) -> ImageFacts {
        match self.kind {
            IssueKind::Malformed => ImageFacts::Malformed {
                reason: self.reason,
            },
            IssueKind::Unsupported => ImageFacts::Unsupported {
                reason: self.reason,
            },
        }
    }
}

enum ReaderParseError<SourceError> {
    Source(SourceError),
    Format(ParseIssue),
}

impl<SourceError> From<ParseIssue> for ReaderParseError<SourceError> {
    fn from(issue: ParseIssue) -> Self {
        Self::Format(issue)
    }
}

#[derive(Clone, Debug)]
struct FatSlice {
    index: usize,
    offset: u64,
    size: u64,
    alignment_exponent: u32,
    cpu_type: u32,
    cpu_subtype: u32,
}

#[derive(Clone, Debug)]
struct FatHeader {
    slices: Vec<FatSlice>,
    range_issues: Vec<Option<ParseIssue>>,
}

/// Parse all thin slices from one bounded file snapshot.
pub fn read_image(bytes: &[u8]) -> ImageFacts {
    match parse_image(bytes) {
        Ok(Some(slices)) => ImageFacts::Parsed { slices },
        Ok(None) => ImageFacts::NotMachO,
        Err(issue) => issue.into_facts(),
    }
}

/// Parse an image by reading only its header, architecture table and load
/// commands. The callback returns fewer than `length` bytes only at EOF.
pub fn read_image_at<SourceError>(
    file_size: u64,
    mut read_at: impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
) -> Result<ImageFacts, SourceError> {
    match parse_image_at(file_size, &mut read_at) {
        Ok(Some(slices)) => Ok(ImageFacts::Parsed { slices }),
        Ok(None) => Ok(ImageFacts::NotMachO),
        Err(ReaderParseError::Source(error)) => Err(error),
        Err(ReaderParseError::Format(issue)) => Ok(issue.into_facts()),
    }
}

fn parse_image_at<SourceError>(
    file_size: u64,
    read_at: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
) -> Result<Option<Vec<Slice>>, ReaderParseError<SourceError>> {
    let head = read_range(read_at, 0, 8)?;
    let Some(magic) = read_u32(&head, 0, false) else {
        let recognized = read_u32(&head, 0, false)
            .is_some_and(|magic| is_macho_magic(magic) || is_fat_magic(magic));
        return if recognized {
            Err(ParseIssue::malformed("Mach-O header is truncated").into())
        } else {
            Ok(None)
        };
    };

    if is_fat_magic(magic) {
        if magic == FAT_MAGIC && file_size <= MAX_LOAD_COMMAND_BYTES as u64 {
            let class_bytes = read_range(read_at, 0, file_size as usize)?;
            if class_bytes.len() as u64 == file_size && is_jvm_class_file(&class_bytes) {
                return Ok(None);
            }
        }
        return parse_fat_image_at(read_at, file_size, magic);
    }

    if matches!(magic, MH_CIGAM | MH_CIGAM_64) {
        if file_size > MAX_SAFE_INTEGER {
            return Err(
                ParseIssue::unsupported("Mach-O file extent exceeds the safe range").into(),
            );
        }
        return parse_thin_slice_at(read_at, file_size, 0, file_size, None)
            .map(|slice| Some(vec![slice]));
    }
    if matches!(magic, MH_MAGIC | MH_MAGIC_64) {
        return Err(ParseIssue::unsupported("big-endian Mach-O images are not supported").into());
    }

    Ok(None)
}

fn parse_fat_image_at<SourceError>(
    read_at: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
    file_size: u64,
    magic: u32,
) -> Result<Option<Vec<Slice>>, ReaderParseError<SourceError>> {
    let Some(header) = read_fat_header_at(read_at, file_size, magic)? else {
        return Ok(None);
    };
    let is_macho = classify_fat_identity_at(read_at, &header)?;
    if !is_macho {
        return Ok(None);
    }

    let mut slices = Vec::with_capacity(header.slices.len());
    let mut unsupported = None;
    for declaration in &header.slices {
        match parse_fat_slice_at(read_at, file_size, declaration) {
            Ok(slice) => slices.push(slice),
            Err(ReaderParseError::Format(issue)) if issue.kind == IssueKind::Unsupported => {
                unsupported.get_or_insert(issue);
            }
            Err(error) => return Err(error),
        }
    }

    if let Some(issue) = unsupported {
        return Err(issue.into());
    }
    Ok(Some(slices))
}

fn read_fat_header_at<SourceError>(
    read_at: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
    file_size: u64,
    magic: u32,
) -> Result<Option<FatHeader>, ReaderParseError<SourceError>> {
    let head = read_range(read_at, 0, 8)?;
    if head.len() < 8 {
        return Err(ParseIssue::malformed("FAT header is truncated").into());
    }
    let little_endian = matches!(magic, FAT_CIGAM | FAT_CIGAM_64);
    let count = read_u32(&head, 4, little_endian)
        .ok_or_else(|| ParseIssue::malformed("FAT header is truncated"))? as usize;
    if count > MAX_FAT_ARCHITECTURES {
        return Ok(None);
    }

    let entry_size = if matches!(magic, FAT_MAGIC_64 | FAT_CIGAM_64) {
        32usize
    } else {
        20usize
    };
    let table_end = count
        .checked_mul(entry_size)
        .and_then(|size| size.checked_add(8))
        .ok_or_else(|| ParseIssue::malformed("FAT architecture table overflows"))?;
    if table_end as u64 > file_size {
        return Err(ParseIssue::malformed("FAT table is truncated").into());
    }

    let table = read_range(read_at, 0, table_end)?;
    if table.len() < table_end {
        return Err(ParseIssue::malformed("FAT table is truncated").into());
    }
    read_fat_header(&table, magic, file_size).map_err(Into::into)
}

fn classify_fat_identity_at<SourceError>(
    read_at: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
    header: &FatHeader,
) -> Result<bool, ReaderParseError<SourceError>> {
    const KNOWN_CPU_TYPES: &[u32] = &[
        7,
        0x0100_0007,
        12,
        0x0100_000c,
        0x0200_000c,
        18,
        0x0100_0012,
    ];
    let has_known_cpu = header
        .slices
        .iter()
        .any(|slice| KNOWN_CPU_TYPES.contains(&slice.cpu_type));
    let invalid_range = header.range_issues.iter().find_map(Clone::clone);
    if has_known_cpu {
        return match invalid_range {
            Some(issue) => Err(issue.into()),
            None => Ok(true),
        };
    }

    for (slice, range_issue) in header.slices.iter().zip(&header.range_issues) {
        if range_issue.is_some() {
            continue;
        }
        let bytes = read_range(read_at, slice.offset, 4)?;
        if read_u32(&bytes, 0, false).is_some_and(is_macho_magic) {
            return match invalid_range {
                Some(issue) => Err(issue.into()),
                None => Ok(true),
            };
        }
    }

    Ok(false)
}

fn parse_fat_slice_at<SourceError>(
    read_at: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
    file_size: u64,
    declaration: &FatSlice,
) -> Result<Slice, ReaderParseError<SourceError>> {
    if let Some(issue) = inspect_fat_slice_range(declaration, file_size, 0) {
        return Err(issue.into());
    }
    let slice = parse_thin_slice_at(
        read_at,
        file_size,
        declaration.offset,
        declaration.size,
        Some((
            declaration.cpu_type,
            declaration.cpu_subtype,
            declaration.alignment_exponent as u8,
        )),
    )?;

    if slice.cpu_type != declaration.cpu_type || slice.cpu_subtype != declaration.cpu_subtype {
        return Err(ParseIssue::malformed(format!(
            "FAT architecture {} CPU type/subtype disagrees with its Mach-O header",
            declaration.index
        ))
        .into());
    }
    Ok(slice)
}

fn parse_thin_slice_at<SourceError>(
    read_at: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
    file_size: u64,
    slice_offset: u64,
    slice_size: u64,
    fat: Option<(u32, u32, u8)>,
) -> Result<Slice, ReaderParseError<SourceError>> {
    let header_probe = read_range(read_at, slice_offset, 4)?;
    let magic = read_u32(&header_probe, 0, false)
        .ok_or_else(|| ParseIssue::malformed("Mach-O header is truncated"))?;
    let header_size = match magic {
        MH_CIGAM => 28usize,
        MH_CIGAM_64 => 32usize,
        MH_MAGIC | MH_MAGIC_64 => {
            return Err(
                ParseIssue::unsupported("big-endian Mach-O slices are not supported").into(),
            );
        }
        _ => {
            return Err(ParseIssue::malformed(format!(
                "slice at offset {slice_offset} has no Mach-O header"
            ))
            .into());
        }
    };

    let header = read_range(read_at, slice_offset, header_size)?;
    if header.len() < header_size {
        return Err(ParseIssue::malformed("Mach-O header is truncated").into());
    }
    let command_bytes = required_u32(&header, 20, true, "Mach-O header is truncated")? as usize;
    if command_bytes > MAX_LOAD_COMMAND_BYTES {
        return Err(ParseIssue::unsupported(format!(
            "load commands occupy {command_bytes} bytes, above the {MAX_LOAD_COMMAND_BYTES}-byte limit"
        ))
        .into());
    }
    let prefix_size = header_size
        .checked_add(command_bytes)
        .ok_or_else(|| ParseIssue::malformed("Mach-O command range overflowed"))?;
    if prefix_size as u64 > slice_size {
        return Err(ParseIssue::malformed("load commands extend beyond the Mach-O slice").into());
    }
    let commands_offset = slice_offset
        .checked_add(header_size as u64)
        .ok_or_else(|| ParseIssue::malformed("Mach-O command range overflowed"))?;
    let commands = read_range(read_at, commands_offset, command_bytes)?;
    if commands.len() < command_bytes {
        return Err(ParseIssue::malformed("load commands extend beyond the Mach-O slice").into());
    }

    let mut header_and_commands = header;
    header_and_commands.extend_from_slice(&commands);
    let available_file_size = file_size.saturating_sub(slice_offset);
    let available_slice_size = slice_size.min(available_file_size);
    parse_thin_slice_with_extent(
        &header_and_commands,
        slice_offset,
        slice_size,
        fat,
        available_slice_size,
    )
    .map_err(Into::into)
}

fn read_range<SourceError>(
    read_at: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SourceError>,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, ReaderParseError<SourceError>> {
    read_at(offset, length).map_err(ReaderParseError::Source)
}

fn parse_image(bytes: &[u8]) -> Result<Option<Vec<Slice>>, ParseIssue> {
    let Some(magic) = read_u32(bytes, 0, false) else {
        return Ok(None);
    };
    if bytes.len() < 8 {
        return if is_macho_magic(magic) {
            Err(ParseIssue::malformed("Mach-O header is truncated"))
        } else {
            Ok(None)
        };
    }

    if is_fat_magic(magic) {
        if magic == FAT_MAGIC && bytes.len() <= MAX_LOAD_COMMAND_BYTES && is_jvm_class_file(bytes) {
            return Ok(None);
        }
        return parse_fat_image(bytes, magic);
    }

    if matches!(magic, MH_CIGAM | MH_CIGAM_64) {
        let slice_size = u64::try_from(bytes.len())
            .map_err(|_| ParseIssue::unsupported("Mach-O file size exceeds the safe range"))?;
        return parse_thin_slice(bytes, 0, slice_size, None).map(|slice| Some(vec![slice]));
    }
    if matches!(magic, MH_MAGIC | MH_MAGIC_64) {
        return Err(ParseIssue::unsupported(
            "big-endian Mach-O images are not supported",
        ));
    }

    Ok(None)
}

fn parse_fat_image(bytes: &[u8], magic: u32) -> Result<Option<Vec<Slice>>, ParseIssue> {
    let Some(header) = read_fat_header(bytes, magic, bytes.len() as u64)? else {
        return Ok(None);
    };
    let is_macho = match classify_fat_identity(bytes, &header) {
        Ok(is_macho) => is_macho,
        Err(issue) if magic == FAT_MAGIC && bytes.len() > MAX_LOAD_COMMAND_BYTES => {
            return Err(ParseIssue::unsupported(
                "FAT/JVM identity is unresolved because the class identity scan exceeds the 16 MiB limit",
            ));
        }
        Err(issue) => return Err(issue),
    };
    if !is_macho {
        return Ok(None);
    }

    let mut slices = Vec::with_capacity(header.slices.len());
    let mut unsupported = None;

    for declaration in &header.slices {
        match parse_fat_slice(bytes, declaration) {
            Ok(slice) => slices.push(slice),
            Err(issue) if issue.kind == IssueKind::Unsupported => {
                unsupported.get_or_insert(issue);
            }
            Err(issue) => return Err(issue),
        }
    }

    if let Some(issue) = unsupported {
        return Err(issue);
    }
    Ok(Some(slices))
}

fn read_fat_header(
    bytes: &[u8],
    magic: u32,
    file_size: u64,
) -> Result<Option<FatHeader>, ParseIssue> {
    let little_endian = matches!(magic, FAT_CIGAM | FAT_CIGAM_64);
    let wide = matches!(magic, FAT_MAGIC_64 | FAT_CIGAM_64);
    let count = read_u32(bytes, 4, little_endian)
        .ok_or_else(|| ParseIssue::malformed("FAT header is truncated"))? as usize;
    if count == 0 {
        return Err(ParseIssue::malformed(
            "FAT header declares no architectures",
        ));
    }
    if count > MAX_FAT_ARCHITECTURES {
        return Ok(None);
    }

    let entry_size = if wide { 32usize } else { 20usize };
    let table_end = count
        .checked_mul(entry_size)
        .and_then(|size| size.checked_add(8))
        .ok_or_else(|| ParseIssue::malformed("FAT architecture table overflows"))?;
    if table_end > bytes.len() {
        return Ok(None);
    }

    let mut slices = Vec::with_capacity(count);
    let mut range_issues = Vec::with_capacity(count);
    for index in 0..count {
        let entry = 8 + index * entry_size;
        let cpu_type = read_u32(bytes, entry, little_endian)
            .ok_or_else(|| ParseIssue::malformed("FAT table is truncated"))?;
        let cpu_subtype = read_u32(bytes, entry + 4, little_endian)
            .ok_or_else(|| ParseIssue::malformed("FAT table is truncated"))?;
        let offset = if wide {
            read_u64(bytes, entry + 8, little_endian)
                .ok_or_else(|| ParseIssue::malformed("FAT table is truncated"))?
        } else {
            u64::from(
                read_u32(bytes, entry + 8, little_endian)
                    .ok_or_else(|| ParseIssue::malformed("FAT table is truncated"))?,
            )
        };
        let size = if wide {
            read_u64(bytes, entry + 16, little_endian)
                .ok_or_else(|| ParseIssue::malformed("FAT table is truncated"))?
        } else {
            u64::from(
                read_u32(bytes, entry + 12, little_endian)
                    .ok_or_else(|| ParseIssue::malformed("FAT table is truncated"))?,
            )
        };
        if offset > 9_007_199_254_740_991 || size > 9_007_199_254_740_991 {
            return Err(ParseIssue::malformed(
                "FAT offset or size exceeds the safe range",
            ));
        }
        let alignment_exponent = read_u32(bytes, entry + if wide { 24 } else { 16 }, little_endian)
            .ok_or_else(|| ParseIssue::malformed("FAT table is truncated"))?;

        let declaration = FatSlice {
            index,
            offset,
            size,
            alignment_exponent,
            cpu_type,
            cpu_subtype,
        };
        range_issues.push(inspect_fat_slice_range(
            &declaration,
            file_size,
            table_end as u64,
        ));
        slices.push(declaration);
    }

    Ok(Some(FatHeader {
        slices,
        range_issues,
    }))
}

fn inspect_fat_slice_range(slice: &FatSlice, file_size: u64, table_end: u64) -> Option<ParseIssue> {
    if slice.size == 0 || slice.offset < table_end {
        return Some(ParseIssue::malformed(format!(
            "FAT architecture {} has an invalid slice range",
            slice.index
        )));
    }
    if slice.offset > file_size || slice.size > file_size.saturating_sub(slice.offset) {
        return Some(ParseIssue::malformed(format!(
            "FAT architecture {} slice range extends beyond the file",
            slice.index
        )));
    }
    if slice.alignment_exponent > 52 {
        return Some(ParseIssue::unsupported(format!(
            "FAT architecture {} alignment exponent {} is unsupported",
            slice.index, slice.alignment_exponent
        )));
    }

    let alignment = 1u64 << slice.alignment_exponent;
    if slice.offset % alignment != 0 {
        return Some(ParseIssue::malformed(format!(
            "FAT architecture {} offset is not aligned to 2^{}",
            slice.index, slice.alignment_exponent
        )));
    }
    None
}

fn classify_fat_identity(bytes: &[u8], header: &FatHeader) -> Result<bool, ParseIssue> {
    const KNOWN_CPU_TYPES: &[u32] = &[
        7,
        0x0100_0007,
        12,
        0x0100_000c,
        0x0200_000c,
        18,
        0x0100_0012,
    ];
    let has_known_cpu = header
        .slices
        .iter()
        .any(|slice| KNOWN_CPU_TYPES.contains(&slice.cpu_type));
    let invalid_range = header.range_issues.iter().find_map(Clone::clone);
    if has_known_cpu {
        return match invalid_range {
            Some(issue) => Err(issue),
            None => Ok(true),
        };
    }

    let contains_macho_slice =
        header
            .slices
            .iter()
            .zip(&header.range_issues)
            .any(|(slice, issue)| {
                if issue.is_some() {
                    return false;
                }
                let Some(offset) = usize::try_from(slice.offset).ok() else {
                    return false;
                };
                read_u32(bytes, offset, false).is_some_and(is_macho_magic)
            });
    if contains_macho_slice {
        match invalid_range {
            Some(issue) => Err(issue),
            None => Ok(true),
        }
    } else {
        Ok(false)
    }
}

fn parse_fat_slice(bytes: &[u8], declaration: &FatSlice) -> Result<Slice, ParseIssue> {
    if let Some(issue) = inspect_fat_slice_range(declaration, bytes.len() as u64, 0) {
        return Err(issue);
    }

    let start = usize::try_from(declaration.offset)
        .map_err(|_| ParseIssue::malformed("FAT offset or size exceeds the safe range"))?;
    let length = usize::try_from(declaration.size)
        .map_err(|_| ParseIssue::malformed("FAT offset or size exceeds the safe range"))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| ParseIssue::malformed("FAT slice range overflows"))?;
    let bytes = bytes
        .get(start..end)
        .ok_or_else(|| ParseIssue::malformed("FAT slice range extends beyond the file"))?;
    let slice = parse_thin_slice(
        bytes,
        u64::from(declaration.offset),
        u64::from(declaration.size),
        Some((
            declaration.cpu_type,
            declaration.cpu_subtype,
            declaration.alignment_exponent as u8,
        )),
    )?;

    if slice.cpu_type != declaration.cpu_type || slice.cpu_subtype != declaration.cpu_subtype {
        return Err(ParseIssue::malformed(format!(
            "FAT architecture {} CPU type/subtype disagrees with its Mach-O header",
            declaration.index
        )));
    }
    Ok(slice)
}

fn parse_thin_slice(
    bytes: &[u8],
    slice_offset: u64,
    slice_size: u64,
    fat: Option<(u32, u32, u8)>,
) -> Result<Slice, ParseIssue> {
    parse_thin_slice_with_extent(bytes, slice_offset, slice_size, fat, bytes.len() as u64)
}

fn parse_thin_slice_with_extent(
    bytes: &[u8],
    slice_offset: u64,
    slice_size: u64,
    fat: Option<(u32, u32, u8)>,
    available_slice_size: u64,
) -> Result<Slice, ParseIssue> {
    let magic = read_u32(bytes, 0, false)
        .ok_or_else(|| ParseIssue::malformed("Mach-O header is truncated"))?;
    let (wide, little_endian) = match magic {
        MH_CIGAM => (false, true),
        MH_CIGAM_64 => (true, true),
        MH_MAGIC | MH_MAGIC_64 => {
            return Err(ParseIssue::unsupported(
                "big-endian Mach-O slices are not supported",
            ));
        }
        _ => {
            return Err(ParseIssue::malformed(format!(
                "slice at offset {slice_offset} has no Mach-O header"
            )));
        }
    };

    let header_size = if wide { 32usize } else { 28usize };
    if bytes.len() < header_size {
        return Err(ParseIssue::malformed("Mach-O header is truncated"));
    }
    let cpu_type = required_u32(bytes, 4, little_endian, "Mach-O header is truncated")?;
    let cpu_subtype = required_u32(bytes, 8, little_endian, "Mach-O header is truncated")?;
    let file_type = required_u32(bytes, 12, little_endian, "Mach-O header is truncated")?;
    let command_count = required_u32(bytes, 16, little_endian, "Mach-O header is truncated")?;
    let command_bytes = required_u32(bytes, 20, little_endian, "Mach-O header is truncated")?;
    let command_count = usize::try_from(command_count)
        .map_err(|_| ParseIssue::malformed("Mach-O command count exceeds the safe range"))?;
    let command_bytes = usize::try_from(command_bytes)
        .map_err(|_| ParseIssue::malformed("Mach-O command size exceeds the safe range"))?;
    if command_bytes > MAX_LOAD_COMMAND_BYTES {
        return Err(ParseIssue::unsupported(format!(
            "load commands occupy {command_bytes} bytes, above the {MAX_LOAD_COMMAND_BYTES}-byte limit"
        )));
    }
    let command_end = header_size
        .checked_add(command_bytes)
        .ok_or_else(|| ParseIssue::malformed("Mach-O command range overflowed"))?;
    if command_end as u64 > slice_size || command_end as u64 > available_slice_size {
        return Err(ParseIssue::malformed(
            "load commands extend beyond the Mach-O slice",
        ));
    }
    if command_end > bytes.len() {
        return Err(ParseIssue::malformed(
            "load commands extend beyond the Mach-O slice",
        ));
    }

    let mut slice = Slice {
        architecture: architecture_name(cpu_type, cpu_subtype),
        slice_offset,
        slice_size,
        cpu_type,
        cpu_subtype,
        fat_cpu_type: fat.map(|value| value.0),
        fat_cpu_subtype: fat.map(|value| value.1),
        fat_alignment_exponent: fat.map(|value| value.2),
        file_type: file_type_name(file_type).to_owned(),
        file_type_code: file_type,
        platform: None,
        platforms: Vec::new(),
        install_name: None,
        dependencies: Vec::new(),
        rpaths: Vec::new(),
        dyld_environment: Vec::new(),
        code_signature_present: false,
    };

    let commands = &bytes[header_size..command_end];
    decode_commands(commands, command_count, wide, cpu_type, &mut slice)?;
    let mut distinct_platforms = Vec::new();
    for platform in &slice.platforms {
        if !distinct_platforms.contains(platform) {
            distinct_platforms.push(*platform);
        }
    }
    slice.platforms = distinct_platforms;
    if slice.platforms.len() == 1 {
        slice.platform = slice.platforms.first().copied();
    }

    Ok(slice)
}

fn decode_commands(
    bytes: &[u8],
    command_count: usize,
    wide: bool,
    cpu_type: u32,
    slice: &mut Slice,
) -> Result<(), ParseIssue> {
    let alignment = if wide { 8 } else { 4 };
    let mut offset = 0usize;
    for index in 0..command_count {
        if offset.saturating_add(8) > bytes.len() {
            return Err(ParseIssue::malformed(format!(
                "load command {index} starts beyond sizeofcmds"
            )));
        }
        let command = required_u32(bytes, offset, true, "load command is truncated")?;
        let size = required_u32(bytes, offset + 4, true, "load command is truncated")? as usize;
        if size < 8 || size % alignment != 0 || offset.saturating_add(size) > bytes.len() {
            return Err(ParseIssue::malformed(format!(
                "load command {index} at offset {offset} has invalid cmdsize {size}"
            )));
        }

        decode_command(
            command,
            &bytes[offset..offset + size],
            index,
            cpu_type,
            slice,
        )?;
        offset += size;
    }

    if offset != bytes.len() {
        return Err(ParseIssue::malformed(format!(
            "load commands declare {command_count} commands but sizeofcmds holds {} bytes",
            bytes.len()
        )));
    }
    Ok(())
}

fn decode_command(
    command: u32,
    body: &[u8],
    index: usize,
    cpu_type: u32,
    slice: &mut Slice,
) -> Result<(), ParseIssue> {
    match command {
        0x0d => slice.install_name = Some(command_string(body, 24, index)?),
        0x8000_001c => slice.rpaths.push(command_string(body, 12, index)?),
        0x27 => slice
            .dyld_environment
            .push(command_string(body, 12, index)?),
        0x1d => {
            if body.len() < 16 {
                return Err(ParseIssue::malformed(format!(
                    "load command {index} is too short for LC_CODE_SIGNATURE"
                )));
            }
            slice.code_signature_present = true;
        }
        0x32 => parse_build_version(body, index, slice)?,
        0x24 | 0x25 | 0x2f | 0x30 => {
            if body.len() < 16 {
                return Err(ParseIssue::malformed(format!(
                    "load command {index} is too short for a version-min command"
                )));
            }
            if let Some(platform) = legacy_platform(command, cpu_type) {
                slice.platforms.push(platform);
            }
        }
        0x0c | 0x8000_0018 | 0x8000_001f | 0x20 | 0x8000_0023 => {
            slice
                .dependencies
                .push(decode_dependency(command, body, index)?);
        }
        _ => {}
    }
    Ok(())
}

fn parse_build_version(body: &[u8], index: usize, slice: &mut Slice) -> Result<(), ParseIssue> {
    if body.len() < 24 {
        return Err(ParseIssue::malformed(format!(
            "load command {index} is too short for LC_BUILD_VERSION"
        )));
    }
    let tool_count = required_u32(body, 20, true, "LC_BUILD_VERSION is truncated")? as usize;
    if tool_count > (body.len() - 24) / 8 {
        return Err(ParseIssue::malformed(format!(
            "load command {index} LC_BUILD_VERSION tool records exceed cmdsize"
        )));
    }
    let platform = required_u32(body, 8, true, "LC_BUILD_VERSION is truncated")?;
    slice.platforms.push(platform);
    Ok(())
}

fn decode_dependency(command: u32, body: &[u8], index: usize) -> Result<Dependency, ParseIssue> {
    if body.len() < 24 {
        return Err(ParseIssue::malformed(format!(
            "load command {index} is too short for a dylib command"
        )));
    }
    let name_offset = required_u32(body, 8, true, "dylib command is truncated")? as usize;
    let uses_flags =
        name_offset == 28 && body.len() >= 28 && read_u32(body, 12, true) == Some(0x1a74_1800);
    let flags = if uses_flags {
        required_u32(body, 24, true, "dylib-use command is truncated")?
    } else {
        0
    };
    let install_name = command_string(body, if uses_flags { 28 } else { 24 }, index)?;
    let command_name = match command {
        0x0c => "LC_LOAD_DYLIB",
        0x8000_0018 => "LC_LOAD_WEAK_DYLIB",
        0x8000_001f => "LC_REEXPORT_DYLIB",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x8000_0023 => "LC_LOAD_UPWARD_DYLIB",
        _ => unreachable!("only dependency commands reach this parser"),
    };
    let base_weak = command == 0x8000_0018;
    let base_reexport = command == 0x8000_001f;
    let base_upward = command == 0x8000_0023;
    let current_version = required_u32(body, 16, true, "dylib command is truncated")?;
    let compatibility_version = required_u32(body, 20, true, "dylib command is truncated")?;

    Ok(Dependency {
        command: command_name.to_owned(),
        encoding: if uses_flags {
            "dylib_use_command"
        } else {
            "dylib_command"
        }
        .to_owned(),
        install_name,
        weak: base_weak || flags & 0x1 != 0,
        upward: base_upward || flags & 0x4 != 0,
        reexport: base_reexport || flags & 0x2 != 0,
        delayed_init: flags & 0x8 != 0,
        current_version: format_version(current_version),
        compatibility_version: format_version(compatibility_version),
    })
}

fn command_string(body: &[u8], minimum_offset: usize, index: usize) -> Result<String, ParseIssue> {
    if body.len() < 12 {
        return Err(ParseIssue::malformed(format!(
            "load command {index} is too short to hold a string offset"
        )));
    }
    let offset = required_u32(body, 8, true, "load command string offset is truncated")? as usize;
    if offset < minimum_offset || offset >= body.len() {
        return Err(ParseIssue::malformed(format!(
            "load command {index} has string offset {offset} outside the command"
        )));
    }
    let raw = &body[offset..];
    let Some(end) = raw.iter().position(|byte| *byte == 0) else {
        return Err(ParseIssue::malformed(format!(
            "load command {index} has an unterminated string"
        )));
    };
    std::str::from_utf8(&raw[..end])
        .map(str::to_owned)
        .map_err(|_| {
            ParseIssue::malformed(format!(
                "load command {index} has a string that is not UTF-8"
            ))
        })
}

fn legacy_platform(command: u32, cpu_type: u32) -> Option<u32> {
    let is_intel = matches!(cpu_type, 7 | 0x0100_0007);
    match command {
        0x24 => Some(1),
        0x25 => Some(if is_intel { 7 } else { 2 }),
        0x2f => Some(if cpu_type == 0x0100_0007 { 8 } else { 3 }),
        0x30 => Some(if is_intel { 9 } else { 4 }),
        _ => None,
    }
}

fn architecture_name(cpu_type: u32, cpu_subtype: u32) -> String {
    let subtype = cpu_subtype & 0x00ff_ffff;
    match cpu_type {
        0x0100_000c if matches!(subtype, 2 | 12) => "arm64e".to_owned(),
        0x0100_000c => "arm64".to_owned(),
        0x0200_000c => "arm64_32".to_owned(),
        0x0100_0007 if subtype == 8 => "x86_64h".to_owned(),
        0x0100_0007 => "x86_64".to_owned(),
        7 => "i386".to_owned(),
        12 => "arm".to_owned(),
        _ => format!("cpu-{cpu_type:x}"),
    }
}

fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
        2 => "execute",
        6 => "dylib",
        8 => "bundle",
        _ => "other",
    }
}

fn format_version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

fn is_fat_magic(magic: u32) -> bool {
    matches!(magic, FAT_MAGIC | FAT_MAGIC_64 | FAT_CIGAM | FAT_CIGAM_64)
}

fn is_macho_magic(magic: u32) -> bool {
    matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let bytes = bytes.get(offset..offset.checked_add(4)?)?;
    let bytes: [u8; 4] = bytes.try_into().ok()?;
    Some(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let bytes = bytes.get(offset..offset.checked_add(8)?)?;
    let bytes: [u8; 8] = bytes.try_into().ok()?;
    Some(if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn required_u32(
    bytes: &[u8],
    offset: usize,
    little_endian: bool,
    reason: &'static str,
) -> Result<u32, ParseIssue> {
    read_u32(bytes, offset, little_endian).ok_or_else(|| ParseIssue::malformed(reason))
}

fn is_jvm_class_file(bytes: &[u8]) -> bool {
    let mut cursor = ClassFileCursor::new(bytes);
    if cursor.u4() != Some(FAT_MAGIC) {
        return false;
    }
    let Some(_minor) = cursor.u2() else {
        return false;
    };
    let Some(major) = cursor.u2() else {
        return false;
    };
    let Some(pool_count) = cursor.u2() else {
        return false;
    };
    if major < 45 || pool_count == 0 {
        return false;
    }

    let Some(pool) = cursor.constant_pool(pool_count, major) else {
        return false;
    };
    if cursor.u2().is_none() {
        return false;
    }
    let Some(this_class) = cursor.u2() else {
        return false;
    };
    let Some(super_class) = cursor.u2() else {
        return false;
    };
    if !pool.has_tag(this_class, &[7]) || (super_class != 0 && !pool.has_tag(super_class, &[7])) {
        return false;
    }

    let Some(interface_count) = cursor.u2() else {
        return false;
    };
    if !cursor.skip(usize::from(interface_count) * 2)
        || !cursor.members(&pool)
        || !cursor.members(&pool)
    {
        return false;
    }
    let Some(attribute_count) = cursor.u2() else {
        return false;
    };
    cursor.attributes(&pool, attribute_count) && cursor.at_end()
}

#[derive(Clone, Copy)]
struct ConstantPoolEntry {
    tag: u8,
    first: u16,
    second: u16,
}

struct ConstantPool {
    entries: Vec<ConstantPoolEntry>,
}

impl ConstantPool {
    fn has_tag(&self, index: u16, tags: &[u8]) -> bool {
        index > 0
            && self
                .entries
                .get(usize::from(index))
                .is_some_and(|entry| tags.contains(&entry.tag))
    }

    fn references_are_valid(&self, major: u16) -> bool {
        for entry in self.entries.iter().skip(1) {
            let first = entry.first;
            let second = entry.second;
            let valid = match entry.tag {
                7 | 8 | 16 | 19 | 20 => {
                    self.has_tag(first, &[1])
                        && !(entry.tag == 16 && major < 51)
                        && !((entry.tag == 19 || entry.tag == 20) && major < 53)
                }
                9 | 10 | 11 => self.has_tag(first, &[7]) && self.has_tag(second, &[12]),
                12 => self.has_tag(first, &[1]) && self.has_tag(second, &[1]),
                15 => self.valid_method_handle(first, second, major),
                17 => self.has_tag(second, &[12]) && major >= 55,
                18 => self.has_tag(second, &[12]) && major >= 51,
                _ => true,
            };
            if !valid {
                return false;
            }
        }
        true
    }

    fn valid_method_handle(&self, kind: u16, reference: u16, major: u16) -> bool {
        if !(1..=9).contains(&kind) || major < 51 {
            return false;
        }
        match kind {
            1..=4 => self.has_tag(reference, &[9]),
            5 | 8 => self.has_tag(reference, &[10]),
            6 | 7 if major >= 52 => self.has_tag(reference, &[10, 11]),
            6 | 7 => self.has_tag(reference, &[10]),
            _ => self.has_tag(reference, &[11]),
        }
    }
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

    fn u1(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.offset)?;
        self.offset += 1;
        Some(value)
    }

    fn u2(&mut self) -> Option<u16> {
        let bytes = self.bytes.get(self.offset..self.offset.checked_add(2)?)?;
        let value = u16::from_be_bytes(bytes.try_into().ok()?);
        self.offset += 2;
        Some(value)
    }

    fn u4(&mut self) -> Option<u32> {
        let bytes = self.bytes.get(self.offset..self.offset.checked_add(4)?)?;
        let value = u32::from_be_bytes(bytes.try_into().ok()?);
        self.offset += 4;
        Some(value)
    }

    fn skip(&mut self, length: usize) -> bool {
        let Some(end) = self.offset.checked_add(length) else {
            return false;
        };
        if end > self.bytes.len() {
            return false;
        }
        self.offset = end;
        true
    }

    fn constant_pool(&mut self, count: u16, major: u16) -> Option<ConstantPool> {
        let mut entries = vec![
            ConstantPoolEntry {
                tag: 0,
                first: 0,
                second: 0,
            };
            usize::from(count)
        ];
        let mut index = 1usize;
        while index < entries.len() {
            let tag = self.u1()?;
            let (first, second) = match tag {
                1 => {
                    let length = usize::from(self.u2()?);
                    if !self.skip(length) {
                        return None;
                    }
                    (0, 0)
                }
                3 | 4 => {
                    self.u4()?;
                    (0, 0)
                }
                5 | 6 => {
                    if index + 1 >= entries.len() || !self.skip(8) {
                        return None;
                    }
                    index += 1;
                    (0, 0)
                }
                7 | 8 | 16 | 19 | 20 => (self.u2()?, 0),
                9 | 10 | 11 | 12 | 17 | 18 => (self.u2()?, self.u2()?),
                15 => (u16::from(self.u1()?), self.u2()?),
                _ => return None,
            };
            entries[index] = ConstantPoolEntry { tag, first, second };
            index += 1;
        }

        let pool = ConstantPool { entries };
        pool.references_are_valid(major).then_some(pool)
    }

    fn attributes(&mut self, pool: &ConstantPool, count: u16) -> bool {
        for _ in 0..count {
            let Some(name) = self.u2() else {
                return false;
            };
            let Some(length) = self.u4() else {
                return false;
            };
            if !pool.has_tag(name, &[1]) || !self.skip(length as usize) {
                return false;
            }
        }
        true
    }

    fn members(&mut self, pool: &ConstantPool) -> bool {
        let Some(count) = self.u2() else {
            return false;
        };
        for _ in 0..count {
            if self.u2().is_none() {
                return false;
            }
            let Some(name) = self.u2() else {
                return false;
            };
            let Some(descriptor) = self.u2() else {
                return false;
            };
            let Some(attribute_count) = self.u2() else {
                return false;
            };
            if !pool.has_tag(name, &[1])
                || !pool.has_tag(descriptor, &[1])
                || !self.attributes(pool, attribute_count)
            {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{ImageFacts, read_image, read_image_at};

    #[test]
    fn reads_only_headers_and_load_commands_from_a_large_image() {
        let mut bytes = thin_image();
        bytes.resize(32 * 1024 * 1024, 0);
        let mut largest_read = 0usize;

        let facts = read_image_at(bytes.len() as u64, |offset, length| {
            largest_read = largest_read.max(length);
            let start = usize::try_from(offset).expect("test offset fits usize");
            let end = start.saturating_add(length).min(bytes.len());
            Ok::<_, ()>(bytes[start.min(bytes.len())..end].to_vec())
        })
        .expect("source reads succeed");

        assert_eq!(facts, read_image(&bytes));
        assert!(
            largest_read < 1024,
            "read unexpectedly requested {largest_read} bytes"
        );
    }

    #[test]
    fn parses_thin_little_endian_executable_and_load_commands() {
        let bytes = thin_image();
        let ImageFacts::Parsed { slices } = read_image(&bytes) else {
            panic!("expected parsed thin image");
        };
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].architecture, "arm64");
        assert_eq!(slices[0].file_type, "execute");
        assert_eq!(slices[0].dependencies[0].install_name, "@rpath/libA.dylib");
        assert_eq!(slices[0].rpaths, ["@loader_path/../Frameworks"]);
        assert_eq!(slices[0].platforms, [1]);
        assert!(slices[0].code_signature_present);
    }

    #[test]
    fn parses_fat_slice_identity_and_rejects_mismatch() {
        let thin = thin_image();
        let fat = fat_image(&thin, 0x0100_000c, 0, 0);
        let ImageFacts::Parsed { slices } = read_image(&fat) else {
            panic!("expected parsed FAT image");
        };
        assert_eq!(slices[0].slice_offset, 28);
        assert_eq!(slices[0].fat_cpu_type, Some(0x0100_000c));

        let mismatch = fat_image(&thin, 0x0100_0007, 0, 0);
        assert!(matches!(
            read_image(&mismatch),
            ImageFacts::Malformed { reason }
                if reason.contains("CPU type/subtype disagrees")
        ));
    }

    #[test]
    fn preserves_malformed_and_unsupported_load_command_facts() {
        let mut malformed = thin_image();
        malformed[32 + 4..32 + 8].copy_from_slice(&10u32.to_le_bytes());
        assert!(matches!(
            read_image(&malformed),
            ImageFacts::Malformed { reason } if reason.contains("invalid cmdsize")
        ));

        let mut unsupported = thin_image();
        unsupported[20..24].copy_from_slice(&((16 * 1024 * 1024 + 1) as u32).to_le_bytes());
        assert!(matches!(
            read_image(&unsupported),
            ImageFacts::Unsupported { reason } if reason.contains("above the 16777216-byte limit")
        ));
    }

    fn thin_image() -> Vec<u8> {
        let mut commands = Vec::new();
        let mut dependency = vec![0u8; 48];
        dependency[0..4].copy_from_slice(&0x8000_0018u32.to_le_bytes());
        dependency[4..8].copy_from_slice(&48u32.to_le_bytes());
        dependency[8..12].copy_from_slice(&24u32.to_le_bytes());
        let install_name = b"@rpath/libA.dylib";
        dependency[24..24 + install_name.len()].copy_from_slice(install_name);
        commands.extend(dependency);

        let mut rpath = vec![0u8; 40];
        rpath[0..4].copy_from_slice(&0x8000_001cu32.to_le_bytes());
        rpath[4..8].copy_from_slice(&40u32.to_le_bytes());
        rpath[8..12].copy_from_slice(&12u32.to_le_bytes());
        let rpath_value = b"@loader_path/../Frameworks";
        rpath[12..12 + rpath_value.len()].copy_from_slice(rpath_value);
        commands.extend(rpath);

        let mut build = vec![0u8; 24];
        build[0..4].copy_from_slice(&0x32u32.to_le_bytes());
        build[4..8].copy_from_slice(&24u32.to_le_bytes());
        build[8..12].copy_from_slice(&1u32.to_le_bytes());
        commands.extend(build);

        let mut signature = vec![0u8; 16];
        signature[0..4].copy_from_slice(&0x1du32.to_le_bytes());
        signature[4..8].copy_from_slice(&16u32.to_le_bytes());
        commands.extend(signature);

        let mut image = vec![0u8; 32];
        image[0..4].copy_from_slice(&0xcffa_edfeu32.to_be_bytes());
        image[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        image[8..12].copy_from_slice(&0u32.to_le_bytes());
        image[12..16].copy_from_slice(&2u32.to_le_bytes());
        image[16..20].copy_from_slice(&4u32.to_le_bytes());
        image[20..24].copy_from_slice(&(commands.len() as u32).to_le_bytes());
        image.extend(commands);
        image
    }

    fn fat_image(thin: &[u8], cpu_type: u32, cpu_subtype: u32, alignment: u32) -> Vec<u8> {
        let offset = 28usize;
        let mut image = vec![0u8; offset];
        image[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        image[4..8].copy_from_slice(&1u32.to_be_bytes());
        image[8..12].copy_from_slice(&cpu_type.to_be_bytes());
        image[12..16].copy_from_slice(&cpu_subtype.to_be_bytes());
        image[16..20].copy_from_slice(&(offset as u32).to_be_bytes());
        image[20..24].copy_from_slice(&(thin.len() as u32).to_be_bytes());
        image[24..28].copy_from_slice(&alignment.to_be_bytes());
        image.extend_from_slice(thin);
        image
    }
}
