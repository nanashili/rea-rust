//! File-backed PE and CLI layout parsing without loading target code.
//!
//! Port of `src/dotnet/ManagedPeReader.ts`.

use super::bytes::{read_u16, read_u32};
use super::failure::{InternalFailure, ManagedParseIssue, ManagedReaderFailure, managed_failure};
use super::pe_machine::{PeArchitecture, decode_pe_machine};

/// A parsed PE section's virtual and raw extents.
#[derive(Clone, Copy)]
pub struct PeSection {
    pub virtual_address: i64,
    pub virtual_size: i64,
    pub raw_offset: i64,
    pub raw_size: i64,
}

/// A PE data directory: RVA and size.
#[derive(Clone, Copy)]
pub struct PeDataDirectory {
    pub rva: i64,
    pub size: i64,
}

/// The admitted CLI header fields.
#[derive(Clone)]
pub struct ManagedCliHeader {
    pub header_offset: i64,
    pub header_size: i64,
    pub runtime_major: u16,
    pub runtime_minor: u16,
    pub metadata: PeDataDirectory,
    pub flags: u32,
    pub entry_point: u32,
    pub resources: PeDataDirectory,
    pub strong_name: PeDataDirectory,
    pub managed_native_header: PeDataDirectory,
    pub ready_to_run_signature: bool,
}

/// `managedCli32BitRequirement`: how the CLI header constrains process bitness.
pub fn managed_cli_32bit_requirement(flags: u32) -> &'static str {
    let pair = flags & 0x0002_0002;
    if pair == 0x0000_0002 {
        "required"
    } else if pair == 0x0002_0002 {
        "preferred"
    } else {
        "none"
    }
}

/// `managedCliIsMixedClrNative`: a clear ILONLY flag without the ReadyToRun
/// signature marks mixed CLR/native code.
pub fn managed_cli_is_mixed_clr_native(cli: &ManagedCliHeader) -> bool {
    (cli.flags & 0x0000_0001) == 0 && !cli.ready_to_run_signature
}

/// The CLI data-directory state the layout reports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CliDirectoryState {
    Absent,
    Present,
    Unreadable,
}

/// The parsed PE/CLI layout, with the RVA mapping closures inlined as methods.
pub struct ManagedPeLayout {
    pub machine: u16,
    pub architecture: PeArchitecture,
    pub optional_header: &'static str,
    pub section_count: u16,
    pub characteristics: u16,
    pub sections: Vec<PeSection>,
    pub cli: Option<ManagedCliHeader>,
    pub cli_directory_state: CliDirectoryState,
    pub cli_issue: Option<ManagedParseIssue>,
}

/// The result of `resolveRva`: file offset and uniquely-mapped available bytes.
struct ResolvedRva {
    offset: i64,
    available: i64,
}

fn require_range(
    bytes: &[u8],
    offset: i64,
    length: i64,
    scope: &str,
) -> Result<(), ManagedReaderFailure> {
    let buffer_len = bytes.len() as i64;
    if offset < 0 || length < 0 || offset > buffer_len - length {
        return Err(managed_failure(
            "invalid-directory",
            scope,
            format!("{scope} leaves the artifact byte range"),
            if offset >= 0 {
                Some(offset as u64)
            } else {
                None
            },
        ));
    }
    Ok(())
}

fn add(left: i64, right: i64, scope: &str) -> Result<i64, ManagedReaderFailure> {
    match left.checked_add(right) {
        Some(result) if result >= left => Ok(result),
        _ => Err(managed_failure(
            "invalid-directory",
            scope,
            format!("{scope} offset arithmetic overflowed"),
            Some(left as u64),
        )),
    }
}

fn architecture_for(machine: u16, managed: bool) -> Result<PeArchitecture, ManagedReaderFailure> {
    match decode_pe_machine(machine as u32) {
        Some(decoded) if !(decoded.native_os_override && !managed) => Ok(decoded.architecture),
        _ => Err(managed_failure(
            "invalid-directory",
            "pe.machine",
            format!("Unsupported PE machine 0x{:04x}", machine),
            None,
        )),
    }
}

fn resolve_rva(
    bytes: &[u8],
    sections: &[PeSection],
    rva: i64,
    size: i64,
    scope: &str,
) -> Result<ResolvedRva, ManagedReaderFailure> {
    if rva < 0 || size < 0 || rva > 0xffff_ffff || (size > 0 && size > 0x1_0000_0000 - rva) {
        return Err(managed_failure(
            "invalid-directory",
            scope,
            format!("{scope} has an invalid RVA range"),
            None,
        ));
    }
    // VirtualSize owns RVA containment; raw size also includes alignment padding.
    let selected_index = sections.iter().position(|section| {
        let within = rva - section.virtual_address;
        section.virtual_size > 0
            && within >= 0
            && within < section.virtual_size
            && size <= section.virtual_size - within
    });
    let selected_index = match selected_index {
        Some(index) => index,
        None => {
            return Err(managed_failure(
                "invalid-directory",
                scope,
                format!("{scope} RVA is not covered by one PE section"),
                None,
            ));
        }
    };
    let selected = sections[selected_index];
    for (index, section) in sections.iter().enumerate() {
        if index == selected_index || section.virtual_size == 0 {
            continue;
        }
        let end = section.virtual_address + section.virtual_size;
        let intersects = if size == 0 {
            rva >= section.virtual_address && rva < end
        } else {
            rva < end && rva + size > section.virtual_address
        };
        if intersects {
            return Err(managed_failure(
                "invalid-directory",
                scope,
                format!("{scope} RVA range has ambiguous overlapping PE section mappings"),
                None,
            ));
        }
    }
    let within = rva - selected.virtual_address;
    if within > selected.raw_size || size > selected.raw_size - within {
        return Err(managed_failure(
            "invalid-directory",
            scope,
            format!("{scope} occupies virtual bytes without file-backed data"),
            None,
        ));
    }
    let offset = add(selected.raw_offset, within, scope)?;
    require_range(bytes, offset, size, scope)?;
    let mut available = (selected.virtual_size - within)
        .min(selected.raw_size - within)
        .min(bytes.len() as i64 - offset)
        .min(0x1_0000_0000 - rva);
    // A future overlap ends the uniquely mapped extent even if the current byte is unique.
    for section in sections {
        if section.virtual_address > rva && section.virtual_size > 0 {
            available = available.min(section.virtual_address - rva);
        }
    }
    Ok(ResolvedRva { offset, available })
}

fn map_rva(
    bytes: &[u8],
    sections: &[PeSection],
    rva: i64,
    size: i64,
    scope: &str,
) -> Result<i64, ManagedReaderFailure> {
    if rva == 0 && size == 0 {
        Ok(0)
    } else {
        Ok(resolve_rva(bytes, sections, rva, size, scope)?.offset)
    }
}

impl ManagedPeLayout {
    /// `rvaToOffset(rva, size, scope)`.
    pub fn rva_to_offset(
        &self,
        bytes: &[u8],
        rva: i64,
        size: i64,
        scope: &str,
    ) -> Result<i64, ManagedReaderFailure> {
        map_rva(bytes, &self.sections, rva, size, scope)
    }

    /// `rvaAvailableBytes(rva, scope)`.
    pub fn rva_available_bytes(
        &self,
        bytes: &[u8],
        rva: i64,
        scope: &str,
    ) -> Result<i64, ManagedReaderFailure> {
        Ok(resolve_rva(bytes, &self.sections, rva, 1, scope)?.available)
    }
}

fn read_directory(bytes: &[u8], offset: i64) -> Result<PeDataDirectory, ManagedReaderFailure> {
    require_range(bytes, offset, 8, "pe.data-directory")?;
    Ok(PeDataDirectory {
        rva: read_u32_at(bytes, offset)? as i64,
        size: read_u32_at(bytes, offset + 4)? as i64,
    })
}

fn read_u32_at(bytes: &[u8], offset: i64) -> Result<u32, ManagedReaderFailure> {
    read_u32(bytes, offset as usize).map_err(internal_as_reader)
}

fn read_u16_at(bytes: &[u8], offset: i64) -> Result<u16, ManagedReaderFailure> {
    read_u16(bytes, offset as usize).map_err(internal_as_reader)
}

/// The PE reader pre-checks ranges with `requireRange` before each raw read, so
/// a raw out-of-range read is not reachable; kept total by mapping to a
/// directory failure with no offset.
fn internal_as_reader(_internal: InternalFailure) -> ManagedReaderFailure {
    managed_failure(
        "invalid-directory",
        "pe",
        "PE read left the artifact byte range",
        None,
    )
}

fn read_cli_header(
    bytes: &[u8],
    sections: &[PeSection],
    directory: PeDataDirectory,
) -> Result<ManagedCliHeader, ManagedReaderFailure> {
    if directory.size < 72 {
        return Err(managed_failure(
            "invalid-cli-header",
            "cli.header",
            "CLI header is shorter than the required 72 bytes",
            None,
        ));
    }
    let offset = map_rva(bytes, sections, directory.rva, 72, "cli.header")?;
    let header_size = read_u32_at(bytes, offset)? as i64;
    if header_size < 72 || header_size > directory.size {
        return Err(managed_failure(
            "invalid-cli-header",
            "cli.header",
            "CLI header size is outside its PE data directory",
            Some(offset as u64),
        ));
    }
    let metadata = read_directory(bytes, offset + 8)?;
    if metadata.rva == 0 || metadata.size == 0 {
        return Err(managed_failure(
            "invalid-cli-header",
            "cli.metadata",
            "CLI metadata directory is absent",
            Some((offset + 8) as u64),
        ));
    }
    let flags = read_u32_at(bytes, offset + 16)?;
    let managed_native_header = read_directory(bytes, offset + 64)?;
    let mut ready_to_run_signature = false;
    if managed_native_header.rva != 0 && managed_native_header.size >= 4 {
        let native_offset = map_rva(
            bytes,
            sections,
            managed_native_header.rva,
            4,
            "cli.managed-native-header",
        )?;
        ready_to_run_signature = read_u32_at(bytes, native_offset)? == 0x0052_5452;
    }
    Ok(ManagedCliHeader {
        header_offset: offset,
        header_size,
        runtime_major: read_u16_at(bytes, offset + 4)?,
        runtime_minor: read_u16_at(bytes, offset + 6)?,
        metadata,
        flags,
        entry_point: read_u32_at(bytes, offset + 20)?,
        resources: read_directory(bytes, offset + 24)?,
        strong_name: read_directory(bytes, offset + 32)?,
        managed_native_header,
        ready_to_run_signature,
    })
}

struct CoffHeader {
    coff: i64,
    machine: u16,
    section_count: u16,
    optional_size: u16,
    characteristics: u16,
}

struct OptionalHeader {
    optional_offset: i64,
    optional_header: &'static str,
    directory_count_offset: i64,
    directory_offset: i64,
}

enum CliDirectoryRead {
    Absent,
    Present(PeDataDirectory),
    Unreadable(ManagedParseIssue),
}

fn read_coff_header(bytes: &[u8]) -> Result<CoffHeader, ManagedReaderFailure> {
    let pe_offset = read_u32_at(bytes, 0x3c)? as i64;
    require_range(bytes, pe_offset, 24, "pe.coff-header")?;
    if read_u32_at(bytes, pe_offset)? != 0x0000_4550 {
        return Err(managed_failure(
            "invalid-directory",
            "pe.signature",
            "PE signature is invalid",
            Some(pe_offset as u64),
        ));
    }
    let coff = pe_offset + 4;
    let machine = read_u16_at(bytes, coff)?;
    let section_count = read_u16_at(bytes, coff + 2)?;
    if section_count == 0 {
        return Err(managed_failure(
            "invalid-directory",
            "pe.sections",
            "PE section count must be positive",
            Some((coff + 2) as u64),
        ));
    }
    let optional_size = read_u16_at(bytes, coff + 16)?;
    let characteristics = read_u16_at(bytes, coff + 18)?;
    Ok(CoffHeader {
        coff,
        machine,
        section_count,
        optional_size,
        characteristics,
    })
}

fn read_optional_header(
    bytes: &[u8],
    coff: &CoffHeader,
) -> Result<OptionalHeader, ManagedReaderFailure> {
    let optional_offset = coff.coff + 20;
    require_range(
        bytes,
        optional_offset,
        coff.optional_size as i64,
        "pe.optional-header",
    )?;
    if coff.optional_size < 96 {
        return Err(managed_failure(
            "invalid-directory",
            "pe.optional-header",
            "PE optional header is too short",
            Some(optional_offset as u64),
        ));
    }
    let magic = read_u16_at(bytes, optional_offset)?;
    let optional_header = match magic {
        0x010b => "pe32",
        0x020b => "pe32-plus",
        _ => {
            return Err(managed_failure(
                "invalid-directory",
                "pe.optional-header",
                "PE optional header magic is unsupported",
                Some(optional_offset as u64),
            ));
        }
    };
    let shift = if optional_header == "pe32" { 92 } else { 108 };
    let dir_shift = if optional_header == "pe32" { 96 } else { 112 };
    Ok(OptionalHeader {
        optional_offset,
        optional_header,
        directory_count_offset: optional_offset + shift,
        directory_offset: optional_offset + dir_shift,
    })
}

fn read_sections(
    bytes: &[u8],
    coff: &CoffHeader,
    optional: &OptionalHeader,
) -> Result<Vec<PeSection>, ManagedReaderFailure> {
    let section_offset = add(
        optional.optional_offset,
        coff.optional_size as i64,
        "pe.sections",
    )?;
    require_range(
        bytes,
        section_offset,
        coff.section_count as i64 * 40,
        "pe.sections",
    )?;
    let mut sections = Vec::with_capacity(coff.section_count as usize);
    for index in 0..coff.section_count as i64 {
        let offset = section_offset + index * 40;
        let section = PeSection {
            virtual_size: read_u32_at(bytes, offset + 8)? as i64,
            virtual_address: read_u32_at(bytes, offset + 12)? as i64,
            raw_size: read_u32_at(bytes, offset + 16)? as i64,
            raw_offset: read_u32_at(bytes, offset + 20)? as i64,
        };
        if section.raw_size > 0 {
            require_range(
                bytes,
                section.raw_offset,
                section.raw_size,
                "pe.section-data",
            )?;
        }
        sections.push(section);
    }
    Ok(sections)
}

fn read_cli_directory(
    bytes: &[u8],
    coff: &CoffHeader,
    optional: &OptionalHeader,
) -> Result<CliDirectoryRead, ManagedReaderFailure> {
    let count_offset = optional.directory_count_offset - optional.optional_offset;
    if count_offset + 4 > coff.optional_size as i64 {
        return Ok(CliDirectoryRead::Unreadable(ManagedParseIssue {
            code: "invalid-directory",
            scope: "pe.optional-header".to_string(),
            detail: "PE optional header does not contain its directory count".to_string(),
            offset: Some(optional.directory_count_offset as u64),
        }));
    }
    let directory_count = read_u32_at(bytes, optional.directory_count_offset)?;
    if directory_count <= 14 {
        return Ok(CliDirectoryRead::Absent);
    }
    // `Math.floor` on a non-negative numerator equals integer division; a
    // negative numerator floors to a value still `< 15`, so truncation keeps
    // the same branch.
    let numerator =
        coff.optional_size as i64 - (optional.directory_offset - optional.optional_offset);
    let available_directory_count = numerator.div_euclid(8);
    if available_directory_count < 15 {
        return Ok(CliDirectoryRead::Unreadable(ManagedParseIssue {
            code: "invalid-directory",
            scope: "pe.data-directories".to_string(),
            detail: "PE data-directory count exceeds the optional-header extent".to_string(),
            offset: Some(optional.directory_count_offset as u64),
        }));
    }
    let directory = read_directory(bytes, optional.directory_offset + 14 * 8)?;
    Ok(if directory.rva != 0 || directory.size != 0 {
        CliDirectoryRead::Present(directory)
    } else {
        CliDirectoryRead::Absent
    })
}

/// Parse the file-backed PE and CLI layout without loading target code.
pub fn read_managed_pe_layout(bytes: &[u8]) -> Result<ManagedPeLayout, ManagedReaderFailure> {
    require_range(bytes, 0, 64, "pe.dos-header")?;
    if bytes.first().copied() != Some(0x4d) || bytes.get(1).copied() != Some(0x5a) {
        return Err(managed_failure(
            "invalid-directory",
            "pe.dos-header",
            "Artifact does not start with an MZ header",
            Some(0),
        ));
    }
    let coff = read_coff_header(bytes)?;
    let optional = read_optional_header(bytes, &coff)?;
    let sections = read_sections(bytes, &coff, &optional)?;
    let cli_directory_read = read_cli_directory(bytes, &coff, &optional)?;
    let cli_directory_state = match cli_directory_read {
        CliDirectoryRead::Absent => CliDirectoryState::Absent,
        CliDirectoryRead::Present(_) => CliDirectoryState::Present,
        CliDirectoryRead::Unreadable(_) => CliDirectoryState::Unreadable,
    };
    let mut cli: Option<ManagedCliHeader> = None;
    let mut cli_issue: Option<ManagedParseIssue> = match &cli_directory_read {
        CliDirectoryRead::Unreadable(issue) => Some(issue.clone()),
        _ => None,
    };
    if let CliDirectoryRead::Present(directory) = cli_directory_read {
        match read_cli_header(bytes, &sections, directory) {
            Ok(header) => cli = Some(header),
            Err(failure) => cli_issue = Some(failure.issue),
        }
    }
    let architecture = architecture_for(
        coff.machine,
        cli_directory_state != CliDirectoryState::Absent,
    )?;
    Ok(ManagedPeLayout {
        machine: coff.machine,
        architecture,
        optional_header: optional.optional_header,
        section_count: coff.section_count,
        characteristics: coff.characteristics,
        sections,
        cli,
        cli_directory_state,
        cli_issue,
    })
}
