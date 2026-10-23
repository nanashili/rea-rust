//! Bounded PE target identity and CodeView inspection.
//!
//! This module owns PE header interpretation for target resolution. It does
//! not read files and does not inspect CLI metadata; those concerns belong to
//! their respective application and managed-artifact owners.

use serde::Serialize;

pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_OPTIONAL_HEADER_BYTES: usize = 4096;
const MAX_DEBUG_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    ResourceLimit(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(reason) | Self::Unsupported(reason) | Self::ResourceLimit(reason) => {
                f.write_str(reason)
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Inspection {
    pub format: &'static str,
    /// Original unsigned COFF machine value, before architecture normalization.
    ///
    /// Keep this separate from `architecture`: ReadyToRun images can carry a
    /// native-OS override in the machine field while still resolving to the
    /// same provider-neutral CPU family.
    pub pe_machine: u16,
    pub machine: u16,
    pub machine_hex: String,
    pub architecture: &'static str,
    pub available_architectures: Vec<&'static str>,
    pub executable_role: &'static str,
    pub managed: bool,
    pub code_view: Option<CodeView>,
    pub mitigations: Mitigations,
    pub imports: Option<Vec<ImportLibrary>>,
    pub exports: Option<ExportDirectory>,
    pub relocations: Option<RelocationDirectory>,
    pub tls: Option<TlsDirectory>,
    pub delay_imports: Option<Vec<DelayImportLibrary>>,
    pub certificates: Option<CertificateTable>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CodeView {
    pub format: &'static str,
    pub pdb_path: String,
    pub pdb_file_name: String,
    pub guid: Option<String>,
    pub age: u32,
    pub data_offset: usize,
    pub data_bytes: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ImportLibrary {
    pub dll_name: String,
    pub symbols: Vec<ImportSymbol>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ImportSymbol {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ExportDirectory {
    pub dll_name: Option<String>,
    pub ordinal_base: u32,
    pub symbols: Vec<ExportSymbol>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ExportSymbol {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub forwarded_to: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RelocationDirectory {
    pub blocks: Vec<RelocationBlock>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RelocationBlock {
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: Vec<RelocationEntry>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RelocationEntry {
    pub relocation_type: u8,
    pub page_offset: u16,
    pub rva: u32,
    pub file_offset: Option<usize>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TlsDirectory {
    pub address_of_callbacks: u64,
    pub callbacks: Vec<TlsCallback>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TlsCallback {
    pub virtual_address: u64,
    pub rva: Option<u32>,
    pub file_offset: Option<usize>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DelayImportLibrary {
    pub dll_name: String,
    pub descriptor_location: FileRange,
    pub name_rva: u32,
    pub name_location: Option<FileRange>,
    pub thunk_rva: Option<u32>,
    pub iat_rva: Option<u32>,
    pub symbols: Vec<DelayImportSymbol>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DelayImportSymbol {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub raw_value: u64,
    pub thunk_rva: u32,
    pub location: FileRange,
    pub name_location: Option<FileRange>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CertificateTable {
    pub location: FileRange,
    pub entries: Vec<CertificateEntry>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CertificateEntry {
    pub location: FileRange,
    pub length: u32,
    pub revision: u16,
    pub certificate_type: u16,
    pub raw: Vec<u8>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FileRange {
    pub offset: usize,
    pub bytes: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Mitigations {
    pub aslr: Option<bool>,
    pub nx: Option<bool>,
    pub cfg: Option<bool>,
    pub high_entropy_va: Option<bool>,
    pub load_config: Option<LoadConfig>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LoadConfig {
    pub file_offset: usize,
    pub size: usize,
    pub guard_flags: Option<u32>,
}

pub fn inspect(bytes: &[u8]) -> Result<Inspection, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::ResourceLimit(
            "PE target exceeds the 256 MiB input budget",
        ));
    }
    let pe_offset = pe_offset(bytes)?;
    let record = bytes
        .get(pe_offset..)
        .ok_or(Error::Malformed("invalid or truncated PE header"))?;
    let (machine, architecture, managed, executable_role, optional_header_size, sections) =
        parse_record(record)?;
    let code_view = parse_code_view(bytes, pe_offset, optional_header_size, sections);
    let mitigations = parse_mitigations(bytes, pe_offset, optional_header_size, sections);
    let (imports, exports, mut limitations) =
        parse_imports_exports(bytes, pe_offset, optional_header_size, sections);
    let (relocations, relocation_issues) =
        parse_relocations(bytes, pe_offset, optional_header_size, sections);
    limitations.extend(relocation_issues);
    let (tls, tls_issues) = parse_tls(bytes, pe_offset, optional_header_size, sections);
    limitations.extend(tls_issues);
    let (delay_imports, delay_issues) =
        parse_delay_imports(bytes, pe_offset, optional_header_size, sections);
    limitations.extend(delay_issues);
    let (certificates, certificate_issues) =
        parse_certificates(bytes, pe_offset, optional_header_size);
    limitations.extend(certificate_issues);
    if code_view.is_none() {
        limitations.push(
            "PE CodeView debug metadata was not observed; PDB identity remains unknown.".into(),
        );
    }
    Ok(Inspection {
        format: "pe",
        pe_machine: machine,
        machine,
        machine_hex: format!("0x{machine:04x}"),
        architecture,
        available_architectures: vec![architecture],
        executable_role,
        managed,
        code_view,
        mitigations,
        imports,
        exports,
        relocations,
        tls,
        delay_imports,
        certificates,
        limitations,
    })
}

fn pe_offset(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.get(0..2) != Some(b"MZ") {
        return Err(Error::Unsupported("target is not an MZ PE image"));
    }
    let offset = read_u32(bytes, 0x3c)? as usize;
    let signature_end = offset
        .checked_add(4)
        .ok_or(Error::Malformed("invalid or truncated PE header"))?;
    if offset < 64 || bytes.get(offset..signature_end) != Some(b"PE\0\0") {
        return Err(Error::Malformed("invalid or truncated PE header"));
    }
    Ok(offset)
}

fn parse_record(
    record: &[u8],
) -> Result<(u16, &'static str, bool, &'static str, usize, u16), Error> {
    if record.len() < 24 || record.get(0..4) != Some(b"PE\0\0") {
        return Err(Error::Malformed("invalid or truncated PE header"));
    }
    let machine = read_u16(record, 4)?;
    let (architecture, native_override) =
        machine_architecture(machine).ok_or(Error::Unsupported("unsupported PE architecture"))?;
    let sections = read_u16(record, 6)?;
    let optional_header_size = read_u16(record, 20)? as usize;
    if optional_header_size > MAX_OPTIONAL_HEADER_BYTES || record.len() < 24 + optional_header_size
    {
        return Err(Error::Malformed("invalid or truncated PE optional header"));
    }
    let optional = &record[24..24 + optional_header_size];
    let managed = managed_status(optional, architecture)?;
    if native_override && !managed {
        return Err(Error::Unsupported("unsupported PE architecture"));
    }
    let characteristics = read_u16(record, 22)?;
    let role = if characteristics & 0x0002 == 0 {
        "non-executable"
    } else if characteristics & 0x2000 == 0 {
        "application"
    } else {
        "shared-library"
    };
    Ok((
        machine,
        architecture,
        managed,
        role,
        optional_header_size,
        sections,
    ))
}

fn machine_architecture(machine: u16) -> Option<(&'static str, bool)> {
    let direct = match machine {
        0x014c => Some("x86"),
        0x8664 => Some("x86_64"),
        0x01c0 | 0x01c2 | 0x01c4 => Some("arm"),
        0xaa64 => Some("arm64"),
        _ => None,
    };
    if let Some(architecture) = direct {
        return Some((architecture, false));
    }
    for override_value in [0x4644u16, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992] {
        if let Some((architecture, _)) = machine_architecture(machine ^ override_value) {
            return Some((architecture, true));
        }
    }
    None
}

fn managed_status(optional: &[u8], architecture: &str) -> Result<bool, Error> {
    let magic = read_u16(optional, 0)?;
    let expected = if architecture == "x86_64" || architecture == "arm64" {
        0x20b
    } else {
        0x10b
    };
    if magic != expected {
        return Err(Error::Malformed(
            "PE optional-header magic does not match its architecture",
        ));
    }
    let directory_offset = if magic == 0x20b { 112 } else { 96 };
    let count_offset = directory_offset - 4;
    let count = read_u32(optional, count_offset)? as usize;
    let required = directory_offset
        .checked_add(
            count
                .checked_mul(8)
                .ok_or(Error::Malformed("truncated PE data-directory table"))?,
        )
        .ok_or(Error::Malformed("truncated PE data-directory table"))?;
    if required > optional.len() {
        return Err(Error::Malformed("truncated PE data-directory table"));
    }
    if count <= 14 {
        return Ok(false);
    }
    let cli = directory_offset + 14 * 8;
    Ok(read_u32(optional, cli)? != 0 || read_u32(optional, cli + 4)? != 0)
}

fn parse_code_view(
    bytes: &[u8],
    pe_offset: usize,
    optional_header_size: usize,
    sections: u16,
) -> Option<CodeView> {
    let optional_start = pe_offset.checked_add(24)?;
    let optional_end = optional_start.checked_add(optional_header_size)?;
    let optional = bytes.get(optional_start..optional_end)?;
    let (debug_rva, debug_size, headers) = debug_directory(optional)?;
    let section_start = optional_end;
    let section_size = usize::from(sections).checked_mul(40)?;
    let section_table = bytes.get(section_start..section_start.checked_add(section_size)?)?;
    let debug_offset = rva_to_file_offset(
        debug_rva,
        section_table,
        sections,
        headers,
        debug_size.min(MAX_DEBUG_BYTES),
    )?;
    let debug_end = debug_offset
        .checked_add(debug_size.min(MAX_DEBUG_BYTES))?
        .min(bytes.len());
    let debug = bytes.get(debug_offset..debug_end)?;
    for entry in debug.chunks_exact(28) {
        if read_u32(entry, 12).ok()? != 2 {
            continue;
        }
        let size = read_u32(entry, 16).ok()? as usize;
        if size < 16 {
            continue;
        }
        let mut data_offset = read_u32(entry, 24).ok()? as usize;
        if data_offset == 0 {
            data_offset = rva_to_file_offset(
                read_u32(entry, 20).ok()?,
                section_table,
                sections,
                headers,
                size.min(MAX_DEBUG_BYTES),
            )?;
        }
        let data_end = data_offset
            .checked_add(size.min(MAX_DEBUG_BYTES))?
            .min(bytes.len());
        let data = bytes.get(data_offset..data_end)?;
        if let Some(code_view) = parse_code_view_data(data, size, data_offset) {
            return Some(code_view);
        }
    }
    None
}

fn parse_imports_exports(
    bytes: &[u8],
    pe_offset: usize,
    optional_header_size: usize,
    sections: u16,
) -> (
    Option<Vec<ImportLibrary>>,
    Option<ExportDirectory>,
    Vec<String>,
) {
    let mut limitations = Vec::new();
    let optional_start = match pe_offset.checked_add(24) {
        Some(value) => value,
        None => return unavailable_directories("PE directory offsets overflowed"),
    };
    let optional_end = match optional_start.checked_add(optional_header_size) {
        Some(value) => value,
        None => return unavailable_directories("PE optional-header range overflowed"),
    };
    let optional = match bytes.get(optional_start..optional_end) {
        Some(value) => value,
        None => return unavailable_directories("PE optional header is truncated"),
    };
    let magic = match read_u16(optional, 0) {
        Ok(value) => value,
        Err(_) => return unavailable_directories("PE optional-header magic is unavailable"),
    };
    let directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return unavailable_directories("PE data directories are unavailable"),
    };
    let count = match read_u32(optional, directory_offset - 4) {
        Ok(value) => value as usize,
        Err(_) => return unavailable_directories("PE data-directory count is unavailable"),
    };
    let section_start = optional_end;
    let section_size = match usize::from(sections).checked_mul(40) {
        Some(value) => value,
        None => return unavailable_directories("PE section table size overflowed"),
    };
    let section_table = match bytes.get(
        section_start
            ..section_start
                .checked_add(section_size)
                .unwrap_or(usize::MAX),
    ) {
        Some(value) => value,
        None => return unavailable_directories("PE section table is truncated"),
    };
    let import_range = directory_range(optional, directory_offset, count, 1)
        .and_then(|(rva, size)| mapped_range(bytes, rva, size, section_table, sections, optional));
    let export_range = directory_range(optional, directory_offset, count, 0)
        .and_then(|(rva, size)| mapped_range(bytes, rva, size, section_table, sections, optional));
    let imports = match import_range {
        Some((offset, size)) => Some(parse_imports(
            bytes,
            offset,
            size,
            section_table,
            sections,
            optional,
        )),
        None => {
            limitations.push("PE import directory was unavailable; imports remain unknown.".into());
            None
        }
    };
    let exports = match export_range {
        Some((offset, size)) => {
            let rva = directory_range(optional, directory_offset, count, 0).map(|entry| entry.0);
            rva.and_then(|rva| {
                parse_exports(bytes, offset, size, rva, section_table, sections, optional)
            })
        }
        None => {
            limitations.push("PE export directory was unavailable; exports remain unknown.".into());
            None
        }
    };
    (imports, exports, limitations)
}

fn unavailable_directories(
    reason: &str,
) -> (
    Option<Vec<ImportLibrary>>,
    Option<ExportDirectory>,
    Vec<String>,
) {
    (
        None,
        None,
        vec![format!("{reason}; imports and exports remain unknown.")],
    )
}

fn parse_mitigations(
    bytes: &[u8],
    pe_offset: usize,
    optional_header_size: usize,
    sections: u16,
) -> Mitigations {
    let unknown = Mitigations {
        aslr: None,
        nx: None,
        cfg: None,
        high_entropy_va: None,
        load_config: None,
    };
    let Some(optional_start) = pe_offset.checked_add(24) else {
        return unknown;
    };
    let Some(optional_end) = optional_start.checked_add(optional_header_size) else {
        return unknown;
    };
    let Some(optional) = bytes.get(optional_start..optional_end) else {
        return unknown;
    };
    let Ok(magic) = read_u16(optional, 0) else {
        return unknown;
    };
    let Ok(dll_characteristics) = read_u16(optional, 70) else {
        return unknown;
    };
    let Some(directory_offset) = (match magic {
        0x10b => Some(96),
        0x20b => Some(112),
        _ => None,
    }) else {
        return unknown;
    };
    let Ok(directory_count) = read_u32(optional, directory_offset - 4) else {
        return unknown;
    };
    let section_start = optional_end;
    let Some(section_size) = usize::from(sections).checked_mul(40) else {
        return unknown;
    };
    let Some(section_end) = section_start.checked_add(section_size) else {
        return unknown;
    };
    let Some(section_table) = bytes.get(section_start..section_end) else {
        return unknown;
    };
    let load_config = directory_range(optional, directory_offset, directory_count as usize, 10)
        .and_then(|(rva, size)| {
            let headers = read_u32(optional, 60).ok()?;
            let file_offset = rva_to_file_offset(
                rva,
                section_table,
                sections,
                headers,
                size.min(MAX_DEBUG_BYTES),
            )?;
            let available = bytes.len().saturating_sub(file_offset).min(size);
            let guard_offset = if magic == 0x20b { 0x90 } else { 0x58 };
            let guard_flags = (available >= guard_offset + 4)
                .then(|| read_u32(bytes, file_offset + guard_offset).ok())
                .flatten();
            Some(LoadConfig {
                file_offset,
                size: available,
                guard_flags,
            })
        });
    let cfg = dll_characteristics & 0x4000 != 0
        || load_config
            .as_ref()
            .and_then(|config| config.guard_flags)
            .is_some_and(|flags| flags & 0x100 != 0);
    Mitigations {
        aslr: Some(dll_characteristics & 0x40 != 0),
        nx: Some(dll_characteristics & 0x100 != 0),
        cfg: Some(cfg),
        high_entropy_va: Some(dll_characteristics & 0x20 != 0),
        load_config,
    }
}

fn parse_relocations(
    bytes: &[u8],
    pe_offset: usize,
    optional_header_size: usize,
    sections: u16,
) -> (Option<RelocationDirectory>, Vec<String>) {
    let Some(optional_start) = pe_offset.checked_add(24) else {
        return (
            None,
            vec!["PE relocation directory is unavailable; relocations remain unknown.".into()],
        );
    };
    let Some(optional_end) = optional_start.checked_add(optional_header_size) else {
        return (
            None,
            vec!["PE relocation directory is unavailable; relocations remain unknown.".into()],
        );
    };
    let Some(optional) = bytes.get(optional_start..optional_end) else {
        return (
            None,
            vec!["PE relocation directory is unavailable; relocations remain unknown.".into()],
        );
    };
    let Ok(magic) = read_u16(optional, 0) else {
        return (
            None,
            vec!["PE relocation directory is unavailable; relocations remain unknown.".into()],
        );
    };
    let directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => {
            return (
                None,
                vec!["PE relocation directory is unavailable; relocations remain unknown.".into()],
            );
        }
    };
    let Ok(count) = read_u32(optional, directory_offset - 4) else {
        return (
            None,
            vec!["PE relocation directory is unavailable; relocations remain unknown.".into()],
        );
    };
    let Some((rva, size)) = directory_range(optional, directory_offset, count as usize, 5) else {
        return (
            None,
            vec!["PE relocation directory is unavailable; relocations remain unknown.".into()],
        );
    };
    let section_size = match usize::from(sections).checked_mul(40) {
        Some(value) => value,
        None => {
            return (
                None,
                vec![
                    "PE relocation section table is unavailable; relocations remain unknown."
                        .into(),
                ],
            );
        }
    };
    let section_start = optional_end;
    let Some(section_table) = bytes.get(
        section_start
            ..section_start
                .checked_add(section_size)
                .unwrap_or(usize::MAX),
    ) else {
        return (
            None,
            vec!["PE relocation section table is truncated; relocations remain unknown.".into()],
        );
    };
    let headers = read_u32(optional, 60).unwrap_or(0);
    let Some(offset) = rva_to_file_offset(
        rva,
        section_table,
        sections,
        headers,
        size.min(MAX_DEBUG_BYTES * 16),
    ) else {
        return (
            None,
            vec!["PE relocation directory could not be mapped; relocations remain unknown.".into()],
        );
    };
    let end = offset
        .saturating_add(size.min(MAX_DEBUG_BYTES * 16))
        .min(bytes.len());
    let mut cursor = offset;
    let mut blocks = Vec::new();
    let mut issues = Vec::new();
    while cursor < end {
        if end - cursor < 8 {
            issues.push("PE relocation directory has a truncated trailing block.".into());
            break;
        }
        let page_rva = read_u32(bytes, cursor).unwrap_or(0);
        let block_size = read_u32(bytes, cursor + 4).unwrap_or(0);
        if block_size < 8 || block_size % 2 != 0 || block_size as usize > end - cursor {
            issues.push("PE relocation directory contains an invalid block size.".into());
            break;
        }
        let entry_count = (block_size as usize - 8) / 2;
        let mut entries = Vec::with_capacity(entry_count.min(4096));
        for index in 0..entry_count.min(4096) {
            let raw =
                u16::from_le_bytes([bytes[cursor + 8 + index * 2], bytes[cursor + 9 + index * 2]]);
            let relocation_type = (raw >> 12) as u8;
            let page_offset = raw & 0x0fff;
            let entry_rva = page_rva.saturating_add(u32::from(page_offset));
            let file_offset = rva_to_file_offset(entry_rva, section_table, sections, headers, 1);
            entries.push(RelocationEntry {
                relocation_type,
                page_offset,
                rva: entry_rva,
                file_offset,
            });
        }
        blocks.push(RelocationBlock {
            page_rva,
            block_size,
            entries,
        });
        cursor += block_size as usize;
    }
    (Some(RelocationDirectory { blocks }), issues)
}

fn parse_tls(
    bytes: &[u8],
    pe_offset: usize,
    optional_header_size: usize,
    sections: u16,
) -> (Option<TlsDirectory>, Vec<String>) {
    let unknown = || {
        (
            None,
            vec!["PE TLS directory is unavailable; TLS callbacks remain unknown.".into()],
        )
    };
    let Some(optional_start) = pe_offset.checked_add(24) else {
        return unknown();
    };
    let Some(optional_end) = optional_start.checked_add(optional_header_size) else {
        return unknown();
    };
    let Some(optional) = bytes.get(optional_start..optional_end) else {
        return unknown();
    };
    let Ok(magic) = read_u16(optional, 0) else {
        return unknown();
    };
    let (directory_offset, pointer_width) = match magic {
        0x10b => (96, 4usize),
        0x20b => (112, 8usize),
        _ => return unknown(),
    };
    let Ok(count) = read_u32(optional, directory_offset - 4) else {
        return unknown();
    };
    let Some((tls_rva, tls_size)) = directory_range(optional, directory_offset, count as usize, 9)
    else {
        return unknown();
    };
    let Some(section_size) = usize::from(sections).checked_mul(40) else {
        return unknown();
    };
    let Some(section_table) =
        bytes.get(optional_end..optional_end.checked_add(section_size).unwrap_or(usize::MAX))
    else {
        return unknown();
    };
    let headers = read_u32(optional, 60).unwrap_or(0);
    let Some(tls_offset) =
        rva_to_file_offset(tls_rva, section_table, sections, headers, tls_size.min(64))
    else {
        return unknown();
    };
    let image_base = if pointer_width == 4 {
        u64::from(read_u32(optional, 28).unwrap_or(0))
    } else {
        read_u64(optional, 24).unwrap_or(0)
    };
    let callbacks_va_offset = tls_offset + if pointer_width == 4 { 12 } else { 24 };
    let Some(address_of_callbacks) = read_pointer(bytes, callbacks_va_offset, pointer_width) else {
        return (
            None,
            vec!["PE TLS directory is truncated; TLS callbacks remain unknown.".into()],
        );
    };
    if address_of_callbacks == 0 {
        return (
            Some(TlsDirectory {
                address_of_callbacks,
                callbacks: Vec::new(),
            }),
            Vec::new(),
        );
    }
    let Some(callbacks_rva) = address_of_callbacks
        .checked_sub(image_base)
        .and_then(|value| u32::try_from(value).ok())
    else {
        return (Some(TlsDirectory { address_of_callbacks, callbacks: Vec::new() }), vec!["TLS callback VA could not be mapped to an image RVA; callback identity remains unknown.".into()]);
    };
    let Some(mut callback_offset) = rva_to_file_offset(
        callbacks_rva,
        section_table,
        sections,
        headers,
        pointer_width,
    ) else {
        return (
            Some(TlsDirectory {
                address_of_callbacks,
                callbacks: Vec::new(),
            }),
            vec![
                "TLS callback array could not be mapped; callback identity remains unknown.".into(),
            ],
        );
    };
    let mut callbacks = Vec::new();
    let mut issues = Vec::new();
    for _ in 0..256 {
        let Some(value) = read_pointer(bytes, callback_offset, pointer_width) else {
            issues.push("TLS callback array is truncated before its terminator.".into());
            break;
        };
        if value == 0 {
            break;
        }
        let rva = value
            .checked_sub(image_base)
            .and_then(|item| u32::try_from(item).ok());
        let file_offset =
            rva.and_then(|item| rva_to_file_offset(item, section_table, sections, headers, 1));
        callbacks.push(TlsCallback {
            virtual_address: value,
            rva,
            file_offset,
        });
        callback_offset = callback_offset.saturating_add(pointer_width);
    }
    if callbacks.len() == 256 {
        issues.push("TLS callback array exceeded the bounded callback count.".into());
    }
    (
        Some(TlsDirectory {
            address_of_callbacks,
            callbacks,
        }),
        issues,
    )
}

fn parse_delay_imports(
    bytes: &[u8],
    pe_offset: usize,
    optional_header_size: usize,
    sections: u16,
) -> (Option<Vec<DelayImportLibrary>>, Vec<String>) {
    let unknown = || {
        (
            None,
            vec!["PE delay-import directory is unavailable; delay imports remain unknown.".into()],
        )
    };
    let Some(optional_start) = pe_offset.checked_add(24) else {
        return unknown();
    };
    let Some(optional_end) = optional_start.checked_add(optional_header_size) else {
        return unknown();
    };
    let Some(optional) = bytes.get(optional_start..optional_end) else {
        return unknown();
    };
    let Ok(magic) = read_u16(optional, 0) else {
        return unknown();
    };
    let (directory_offset, width) = match magic {
        0x10b => (96, 4usize),
        0x20b => (112, 8usize),
        _ => return unknown(),
    };
    let Ok(count) = read_u32(optional, directory_offset - 4) else {
        return unknown();
    };
    let Some((rva, size)) = directory_range(optional, directory_offset, count as usize, 13) else {
        return unknown();
    };
    let Some(section_size) = usize::from(sections).checked_mul(40) else {
        return unknown();
    };
    let Some(section_table) =
        bytes.get(optional_end..optional_end.checked_add(section_size).unwrap_or(usize::MAX))
    else {
        return unknown();
    };
    let headers = read_u32(optional, 60).unwrap_or(0);
    let Some(offset) = rva_to_file_offset(
        rva,
        section_table,
        sections,
        headers,
        size.min(MAX_DEBUG_BYTES * 16),
    ) else {
        return (
            None,
            vec![
                "PE delay-import directory could not be mapped; delay imports remain unknown."
                    .into(),
            ],
        );
    };
    let end = offset
        .saturating_add(size.min(MAX_DEBUG_BYTES * 16))
        .min(bytes.len());
    let image_base = if width == 4 {
        u64::from(read_u32(optional, 28).unwrap_or(0))
    } else {
        read_u64(optional, 24).unwrap_or(0)
    };
    let mut libraries = Vec::new();
    let mut issues = Vec::new();
    let mut cursor = offset;
    while cursor < end && libraries.len() < 4096 {
        if end - cursor < 32 {
            issues.push("PE delay-import directory has a truncated descriptor.".into());
            break;
        }
        let attrs = read_u32(bytes, cursor).unwrap_or(0);
        let name_field = read_pointer(bytes, cursor + 4, width).unwrap_or(0);
        let iat_field = read_pointer(bytes, cursor + 12, width).unwrap_or(0);
        let int_field = read_pointer(bytes, cursor + 16, width).unwrap_or(0);
        if attrs == 0 && name_field == 0 && iat_field == 0 && int_field == 0 {
            break;
        }
        let to_rva = |value: u64| {
            if attrs & 1 != 0 {
                u32::try_from(value).ok()
            } else {
                value
                    .checked_sub(image_base)
                    .and_then(|item| u32::try_from(item).ok())
            }
        };
        let Some(name_rva) = to_rva(name_field) else {
            issues.push("PE delay-import DLL name could not be mapped.".into());
            cursor += 32;
            continue;
        };
        let Some(dll_name) = rva_string(bytes, name_rva, section_table, sections, optional) else {
            issues.push("PE delay-import DLL name is unreadable.".into());
            cursor += 32;
            continue;
        };
        let thunk_rva = to_rva(if int_field != 0 { int_field } else { iat_field });
        let symbols = thunk_rva
            .map(|value| {
                parse_delay_import_symbols(bytes, value, width, optional, section_table, sections)
            })
            .unwrap_or_default();
        let name_location = rva_to_file_offset(name_rva, section_table, sections, headers, 1)
            .and_then(|name_offset| {
                let length = bytes
                    .get(name_offset..)?
                    .iter()
                    .position(|byte| *byte == 0)?
                    + 1;
                Some(FileRange {
                    offset: name_offset,
                    bytes: length,
                })
            });
        libraries.push(DelayImportLibrary {
            dll_name,
            descriptor_location: FileRange {
                offset: cursor,
                bytes: 32,
            },
            name_rva,
            name_location,
            thunk_rva,
            iat_rva: to_rva(iat_field),
            symbols,
        });
        cursor += 32;
    }
    if libraries.len() == 4096 {
        issues.push("PE delay-import descriptor count exceeded the bounded limit.".into());
    }
    (Some(libraries), issues)
}

fn parse_delay_import_symbols(
    bytes: &[u8],
    rva: u32,
    width: usize,
    optional: &[u8],
    section_table: &[u8],
    sections: u16,
) -> Vec<DelayImportSymbol> {
    let headers = read_u32(optional, 60).unwrap_or(0);
    let Some(mut cursor) = rva_to_file_offset(rva, section_table, sections, headers, width) else {
        return Vec::new();
    };
    let mut symbols = Vec::new();
    for _ in 0..4096 {
        let Some(entry) = bytes.get(cursor..cursor.saturating_add(width)) else {
            break;
        };
        let raw_value = if width == 8 {
            u64::from_le_bytes(entry.try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(entry.try_into().unwrap()))
        };
        if raw_value == 0 {
            break;
        }
        let ordinal_bit = if width == 8 { 1u64 << 63 } else { 1u64 << 31 };
        let (name, ordinal, hint, name_location) = if raw_value & ordinal_bit != 0 {
            (None, Some((raw_value & 0xffff) as u16), None, None)
        } else {
            let name_rva = raw_value as u32;
            let Some(name_offset) =
                rva_to_file_offset(name_rva, section_table, sections, headers, 2)
            else {
                break;
            };
            let Some(hint) = read_u16(bytes, name_offset).ok() else {
                break;
            };
            let name = c_string(bytes, name_offset + 2);
            let name_location = name.as_ref().and_then(|_| {
                let length = bytes
                    .get(name_offset + 2..)?
                    .iter()
                    .position(|byte| *byte == 0)?
                    + 3;
                Some(FileRange {
                    offset: name_offset,
                    bytes: length,
                })
            });
            (name, None, Some(hint), name_location)
        };
        symbols.push(DelayImportSymbol {
            name,
            ordinal,
            hint,
            raw_value,
            thunk_rva: rva.saturating_add((symbols.len() * width) as u32),
            location: FileRange {
                offset: cursor,
                bytes: width,
            },
            name_location,
        });
        cursor = cursor.saturating_add(width);
    }
    symbols
}

fn parse_certificates(
    bytes: &[u8],
    pe_offset: usize,
    optional_header_size: usize,
) -> (Option<CertificateTable>, Vec<String>) {
    let unknown = || {
        (
            None,
            vec!["PE certificate table is unavailable; signature metadata remains unknown.".into()],
        )
    };
    let Some(optional_start) = pe_offset.checked_add(24) else {
        return unknown();
    };
    let Some(optional_end) = optional_start.checked_add(optional_header_size) else {
        return unknown();
    };
    let Some(optional) = bytes.get(optional_start..optional_end) else {
        return unknown();
    };
    let Ok(magic) = read_u16(optional, 0) else {
        return unknown();
    };
    let directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return unknown(),
    };
    let Ok(count) = read_u32(optional, directory_offset - 4) else {
        return unknown();
    };
    let Some((file_offset, size)) = directory_range(optional, directory_offset, count as usize, 4)
    else {
        return unknown();
    };
    let start = file_offset as usize;
    let end = start
        .saturating_add(size.min(MAX_DEBUG_BYTES * 16))
        .min(bytes.len());
    if start >= end {
        return (
            None,
            vec!["PE certificate table is truncated; signature metadata remains unknown.".into()],
        );
    }
    let mut cursor = start;
    let mut entries = Vec::new();
    let mut issues = Vec::new();
    while cursor < end && entries.len() < 4096 {
        if end - cursor < 8 {
            issues.push("PE certificate table has a truncated WIN_CERTIFICATE header.".into());
            break;
        }
        let length = read_u32(bytes, cursor).unwrap_or(0);
        if length < 8 || length as usize > end - cursor {
            issues.push("PE certificate table contains an invalid WIN_CERTIFICATE length.".into());
            break;
        }
        let entry_end = cursor + length as usize;
        let raw = bytes[cursor + 8..entry_end].to_vec();
        entries.push(CertificateEntry {
            location: FileRange {
                offset: cursor,
                bytes: length as usize,
            },
            length,
            revision: read_u16(bytes, cursor + 4).unwrap_or(0),
            certificate_type: read_u16(bytes, cursor + 6).unwrap_or(0),
            raw,
        });
        let aligned = (length as usize + 7) & !7;
        let Some(next) = cursor.checked_add(aligned) else {
            break;
        };
        if next > end && entry_end < end {
            issues.push("PE certificate table has a truncated alignment gap.".into());
            break;
        }
        cursor = next;
    }
    if entries.len() == 4096 {
        issues.push("PE certificate entry count exceeded the bounded limit.".into());
    }
    issues.push(
        "Certificate bytes are observed only; trust and signature validity are not established."
            .into(),
    );
    (
        Some(CertificateTable {
            location: FileRange {
                offset: start,
                bytes: end - start,
            },
            entries,
        }),
        issues,
    )
}

fn directory_range(
    optional: &[u8],
    directory_offset: usize,
    count: usize,
    index: usize,
) -> Option<(u32, usize)> {
    if count <= index {
        return None;
    }
    let offset = directory_offset.checked_add(index.checked_mul(8)?)?;
    let rva = read_u32(optional, offset).ok()?;
    let size = read_u32(optional, offset.checked_add(4)?).ok()? as usize;
    if rva == 0 || size == 0 {
        None
    } else {
        Some((rva, size))
    }
}

fn mapped_range(
    bytes: &[u8],
    rva: u32,
    size: usize,
    section_table: &[u8],
    sections: u16,
    optional: &[u8],
) -> Option<(usize, usize)> {
    let headers = read_u32(optional, 60).ok()?;
    let bounded_size = size.min(MAX_DEBUG_BYTES * 16);
    let offset = rva_to_file_offset(rva, section_table, sections, headers, bounded_size)?;
    let end = offset.checked_add(bounded_size)?.min(bytes.len());
    (end > offset).then_some((offset, end - offset))
}

fn parse_imports(
    bytes: &[u8],
    offset: usize,
    size: usize,
    section_table: &[u8],
    sections: u16,
    optional: &[u8],
) -> Vec<ImportLibrary> {
    let mut libraries = Vec::new();
    let end = offset.saturating_add(size).min(bytes.len());
    let mut cursor = offset;
    while cursor.checked_add(20).is_some_and(|value| value <= end) && libraries.len() < 4096 {
        let descriptor = &bytes[cursor..cursor + 20];
        let lookup_rva = read_u32(descriptor, 0).unwrap_or(0);
        let name_rva = read_u32(descriptor, 12).unwrap_or(0);
        let first_thunk = read_u32(descriptor, 16).unwrap_or(0);
        if lookup_rva == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let name = rva_string(bytes, name_rva, section_table, sections, optional);
        let Some(dll_name) = name else {
            cursor += 20;
            continue;
        };
        let thunk_rva = if lookup_rva != 0 {
            lookup_rva
        } else {
            first_thunk
        };
        let symbols = parse_import_symbols(bytes, thunk_rva, optional, section_table, sections);
        libraries.push(ImportLibrary { dll_name, symbols });
        cursor += 20;
    }
    libraries
}

fn parse_import_symbols(
    bytes: &[u8],
    rva: u32,
    optional: &[u8],
    section_table: &[u8],
    sections: u16,
) -> Vec<ImportSymbol> {
    let is_64 = read_u16(optional, 0).ok() == Some(0x20b);
    let width = if is_64 { 8 } else { 4 };
    let headers = read_u32(optional, 60).unwrap_or(0);
    let Some(mut cursor) = rva_to_file_offset(rva, section_table, sections, headers, width) else {
        return Vec::new();
    };
    let mut symbols = Vec::new();
    for _ in 0..4096 {
        let Some(end) = cursor.checked_add(width) else {
            break;
        };
        let Some(entry) = bytes.get(cursor..end) else {
            break;
        };
        let value = if is_64 {
            u64::from_le_bytes(entry.try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(entry.try_into().unwrap()))
        };
        if value == 0 {
            break;
        }
        if (is_64 && value & (1u64 << 63) != 0) || (!is_64 && value & (1u64 << 31) != 0) {
            symbols.push(ImportSymbol {
                name: None,
                ordinal: Some((value & 0xffff) as u16),
                hint: None,
            });
        } else {
            let name_rva = value as u32;
            let Some(name_offset) =
                rva_to_file_offset(name_rva, section_table, sections, headers, 2)
            else {
                break;
            };
            let Some(hint) = read_u16(bytes, name_offset).ok() else {
                break;
            };
            let name = c_string(bytes, name_offset + 2);
            symbols.push(ImportSymbol {
                name,
                ordinal: None,
                hint: Some(hint),
            });
        }
        cursor = end;
    }
    symbols
}

fn parse_exports(
    bytes: &[u8],
    offset: usize,
    size: usize,
    directory_rva: u32,
    section_table: &[u8],
    sections: u16,
    optional: &[u8],
) -> Option<ExportDirectory> {
    let directory = bytes.get(offset..offset.checked_add(40)?.min(bytes.len()))?;
    if directory.len() < 40 {
        return None;
    }
    let name_rva = read_u32(directory, 12).ok()?;
    let ordinal_base = read_u32(directory, 16).ok()?;
    let function_count = read_u32(directory, 20).ok()? as usize;
    let name_count = read_u32(directory, 24).ok()? as usize;
    if function_count > 4096 || name_count > 4096 {
        return None;
    }
    let functions_rva = read_u32(directory, 28).ok()?;
    let names_rva = read_u32(directory, 32).ok()?;
    let ordinals_rva = read_u32(directory, 36).ok()?;
    let headers = read_u32(optional, 60).ok()?;
    let function_offset = rva_to_file_offset(
        functions_rva,
        section_table,
        sections,
        headers,
        function_count.checked_mul(4)?,
    )?;
    let name_offset = rva_to_file_offset(
        names_rva,
        section_table,
        sections,
        headers,
        name_count.checked_mul(4)?,
    )?;
    let ordinal_offset = rva_to_file_offset(
        ordinals_rva,
        section_table,
        sections,
        headers,
        name_count.checked_mul(2)?,
    )?;
    let mut symbols: Vec<ExportSymbol> = (0..function_count)
        .map(|index| {
            let rva = read_u32(bytes, function_offset + index * 4).unwrap_or(0);
            ExportSymbol {
                name: None,
                ordinal: ordinal_base + index as u32,
                rva,
                forwarded_to: if rva >= directory_rva
                    && rva < directory_rva.checked_add(size as u32).unwrap_or(u32::MAX)
                {
                    rva_string(bytes, rva, section_table, sections, optional)
                } else {
                    None
                },
            }
        })
        .collect();
    for index in 0..name_count {
        let Some(name_rva) = read_u32(bytes, name_offset + index * 4).ok() else {
            continue;
        };
        let Some(name) = rva_string(bytes, name_rva, section_table, sections, optional) else {
            continue;
        };
        let Some(name_ordinal) = read_u16(bytes, ordinal_offset + index * 2).ok() else {
            continue;
        };
        if let Some(symbol) = symbols.get_mut(name_ordinal as usize) {
            symbol.name = Some(name);
        }
    }
    let dll_name = rva_string(bytes, name_rva, section_table, sections, optional);
    Some(ExportDirectory {
        dll_name,
        ordinal_base,
        symbols,
    })
}

fn rva_string(
    bytes: &[u8],
    rva: u32,
    section_table: &[u8],
    sections: u16,
    optional: &[u8],
) -> Option<String> {
    let headers = read_u32(optional, 60).ok()?;
    let offset = rva_to_file_offset(rva, section_table, sections, headers, 1)?;
    c_string(bytes, offset)
}

fn c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let bytes = bytes.get(offset..offset.saturating_add(MAX_DEBUG_BYTES))?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    (!bytes[..end].is_empty()).then(|| String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn debug_directory(optional: &[u8]) -> Option<(u32, usize, u32)> {
    let magic = read_u16(optional, 0).ok()?;
    let directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return None,
    };
    let count = read_u32(optional, directory_offset - 4).ok()?;
    if count <= 6 {
        return None;
    }
    let entry = directory_offset + 6 * 8;
    let rva = read_u32(optional, entry).ok()?;
    let size = read_u32(optional, entry + 4).ok()? as usize;
    if rva == 0 || size < 28 {
        return None;
    }
    Some((rva, size, read_u32(optional, 60).ok()?))
}

fn rva_to_file_offset(
    rva: u32,
    table: &[u8],
    sections: u16,
    headers: u32,
    size: usize,
) -> Option<usize> {
    let rva = rva as usize;
    let headers = headers as usize;
    if rva < headers && size <= headers - rva {
        return Some(rva);
    }
    for section in table.chunks_exact(40).take(usize::from(sections)) {
        let virtual_address = read_u32(section, 12).ok()? as usize;
        let raw_size = read_u32(section, 16).ok()? as usize;
        let raw_pointer = read_u32(section, 20).ok()? as usize;
        if raw_pointer > 0
            && rva >= virtual_address
            && rva - virtual_address < raw_size
            && size <= raw_size - (rva - virtual_address)
        {
            return raw_pointer.checked_add(rva - virtual_address);
        }
    }
    None
}

fn parse_code_view_data(data: &[u8], declared_size: usize, data_offset: usize) -> Option<CodeView> {
    if declared_size < 16 || data.len() < 16 {
        return None;
    }
    let magic = data.get(0..4)?;
    let (format, path_offset) = if magic == b"RSDS" {
        ("RSDS", 24)
    } else if magic == b"NB10" {
        ("NB10", 16)
    } else {
        return None;
    };
    if declared_size <= path_offset || data.len() <= path_offset {
        return None;
    }
    let end = data[path_offset..].iter().position(|byte| *byte == 0)? + path_offset;
    if end <= path_offset || end > declared_size {
        return None;
    }
    let pdb_path = String::from_utf8_lossy(&data[path_offset..end]).into_owned();
    let pdb_file_name = pdb_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&pdb_path)
        .to_owned();
    let (guid, age) = if format == "RSDS" {
        if declared_size < 24 || data.len() < 24 {
            return None;
        }
        let guid = format!(
            "{:08x}-{:04x}-{:04x}-{}-{}",
            read_u32(data, 4).ok()?,
            read_u16(data, 8).ok()?,
            read_u16(data, 10).ok()?,
            hex(&data[12..14]),
            hex(&data[14..20])
        );
        (Some(guid), read_u32(data, 20).ok()?)
    } else {
        (None, read_u32(data, 12).ok()?)
    };
    Some(CodeView {
        format,
        pdb_path,
        pdb_file_name,
        guid,
        age,
        data_offset,
        data_bytes: declared_size.min(data.len()),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset
        .checked_add(2)
        .ok_or(Error::Malformed("truncated PE header"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(Error::Malformed("truncated PE header"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset
        .checked_add(4)
        .ok_or(Error::Malformed("truncated PE header"))?;
    let value = bytes
        .get(offset..end)
        .ok_or(Error::Malformed("truncated PE header"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let value = bytes.get(offset..end)?;
    Some(u64::from_le_bytes(value.try_into().ok()?))
}

fn read_pointer(bytes: &[u8], offset: usize, width: usize) -> Option<u64> {
    match width {
        4 => Some(u64::from(read_u32(bytes, offset).ok()?)),
        8 => read_u64(bytes, offset),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_the_raw_coff_machine_for_os_overridden_targets() {
        let mut bytes = fixture(0x014c ^ 0x4644, 0x10b);
        bytes[0xf4..0xf8].copy_from_slice(&15u32.to_le_bytes());
        bytes[0x168..0x16c].copy_from_slice(&1u32.to_le_bytes());
        let result = inspect(&bytes).expect("valid managed PE header");

        assert_eq!(result.pe_machine, 0x014c ^ 0x4644);
        assert_eq!(result.machine, result.pe_machine);
        assert_eq!(result.architecture, "x86");
        assert!(result.managed);
    }

    #[test]
    fn rejects_a_data_directory_count_that_leaves_the_optional_header() {
        let mut bytes = fixture(0x014c, 0x10b);
        bytes[0xf4..0xf8].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(
            inspect(&bytes),
            Err(Error::Malformed("truncated PE data-directory table"))
        );
    }

    #[test]
    fn parses_rsds_codeview_from_valid_pe_fixture() {
        let mut bytes = fixture(0x014c, 0x10b);
        let cv = 0x500usize;
        bytes[cv..cv + 4].copy_from_slice(b"RSDS");
        bytes[cv + 4..cv + 8].copy_from_slice(&0x12345678u32.to_le_bytes());
        bytes[cv + 8..cv + 10].copy_from_slice(&0x1234u16.to_le_bytes());
        bytes[cv + 10..cv + 12].copy_from_slice(&0x5678u16.to_le_bytes());
        bytes[cv + 12..cv + 20].copy_from_slice(&[0x90, 0xab, 0xcd, 0xef, 1, 2, 3, 4]);
        bytes[cv + 20..cv + 24].copy_from_slice(&3u32.to_le_bytes());
        bytes[0x310..0x314].copy_from_slice(&41u32.to_le_bytes());
        bytes[cv + 24..cv + 41].copy_from_slice(b"C:\\build\\app.pdb\0");
        let result = inspect(&bytes).expect("valid PE");
        let code_view = result.code_view.expect("CodeView");
        assert_eq!(code_view.pdb_path, "C:\\build\\app.pdb");
        assert_eq!(code_view.pdb_file_name, "app.pdb");
        assert_eq!(
            code_view.guid.as_deref(),
            Some("12345678-1234-5678-90ab-cdef01020304")
        );
        assert_eq!(code_view.age, 3);
        assert_eq!(code_view.data_offset, 0x500);
        assert_eq!(code_view.data_bytes, 41);
    }

    #[test]
    fn malformed_codeview_is_an_unknown_with_complete_target_facts() {
        let mut bytes = fixture(0x8664, 0x20b);
        bytes[0x500..0x504].copy_from_slice(b"RSDS");
        let result = inspect(&bytes).expect("PE header remains valid");
        assert!(result.code_view.is_none());
        assert!(
            result
                .limitations
                .iter()
                .any(|limitation| limitation.contains("remains unknown"))
        );
    }

    #[test]
    fn inventories_imports_exports_and_forwarded_symbols() {
        let mut bytes = fixture(0x014c, 0x10b);
        // Import directory (RVA 0x1200 -> file offset 0x400).
        bytes[0x100..0x104].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&40u32.to_le_bytes());
        bytes[0x400..0x404].copy_from_slice(&0x1400u32.to_le_bytes());
        bytes[0x40c..0x410].copy_from_slice(&0x1500u32.to_le_bytes());
        bytes[0x410..0x414].copy_from_slice(&0x1400u32.to_le_bytes());
        bytes[0x600..0x604].copy_from_slice(&0x1550u32.to_le_bytes());
        bytes[0x604..0x608].copy_from_slice(&0x80000007u32.to_le_bytes());
        bytes[0x608..0x60c].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x700..0x70d].copy_from_slice(b"KERNEL32.dll\0");
        bytes[0x750..0x752].copy_from_slice(&9u16.to_le_bytes());
        bytes[0x752..0x759].copy_from_slice(b"Create\0");
        // Export directory (RVA 0x1600 -> file offset 0x800).
        bytes[0xf8..0xfc].copy_from_slice(&0x1600u32.to_le_bytes());
        bytes[0xfc..0x100].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[0x800 + 12..0x800 + 16].copy_from_slice(&0x1a00u32.to_le_bytes());
        bytes[0x800 + 16..0x800 + 20].copy_from_slice(&7u32.to_le_bytes());
        bytes[0x800 + 20..0x800 + 24].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x800 + 24..0x800 + 28].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x800 + 28..0x800 + 32].copy_from_slice(&0x1700u32.to_le_bytes());
        bytes[0x800 + 32..0x800 + 36].copy_from_slice(&0x1800u32.to_le_bytes());
        bytes[0x800 + 36..0x800 + 40].copy_from_slice(&0x1900u32.to_le_bytes());
        bytes[0x1200..0x1209].copy_from_slice(b"demo.dll\0");
        bytes[0x900..0x904].copy_from_slice(&0x1650u32.to_le_bytes());
        bytes[0x904..0x908].copy_from_slice(&0x1111u32.to_le_bytes());
        bytes[0xa00..0xa04].copy_from_slice(&0x1a20u32.to_le_bytes());
        bytes[0xb00..0xb02].copy_from_slice(&0u16.to_le_bytes());
        bytes[0x850..0x85b].copy_from_slice(b"OTHER.Func\0");
        bytes[0xc20..0xc25].copy_from_slice(b"Open\0");
        let result = inspect(&bytes).expect("valid PE");
        assert_eq!(result.imports.as_ref().unwrap()[0].dll_name, "KERNEL32.dll");
        assert_eq!(result.imports.as_ref().unwrap()[0].symbols[0].ordinal, None);
        assert_eq!(result.imports.as_ref().unwrap()[0].symbols[0].hint, Some(9));
        assert_eq!(result.exports.as_ref().unwrap().ordinal_base, 7);
        assert_eq!(
            result.exports.as_ref().unwrap().symbols[0].name.as_deref(),
            Some("Open")
        );
        assert_eq!(
            result.exports.as_ref().unwrap().symbols[0]
                .forwarded_to
                .as_deref(),
            Some("OTHER.Func")
        );
    }

    #[test]
    fn decodes_pe_mitigations_and_load_config_guard_flags() {
        let mut bytes = fixture(0x8664, 0x20b);
        bytes[0xde..0xe0].copy_from_slice(&0x4160u16.to_le_bytes());
        // PE32+ data directory index 10 is at optional-header offset 192.
        bytes[0x98 + 108..0x98 + 112].copy_from_slice(&11u32.to_le_bytes());
        bytes[0x98 + 112 + 80..0x98 + 112 + 84].copy_from_slice(&0x1b00u32.to_le_bytes());
        bytes[0x98 + 112 + 84..0x98 + 112 + 88].copy_from_slice(&0x100u32.to_le_bytes());
        let load_config_offset = 0x200 + (0x1b00 - 0x1000);
        bytes[load_config_offset + 0x90..load_config_offset + 0x94]
            .copy_from_slice(&0x100u32.to_le_bytes());
        let result = inspect(&bytes).expect("valid PE");
        assert_eq!(result.mitigations.aslr, Some(true));
        assert_eq!(result.mitigations.nx, Some(true));
        assert_eq!(result.mitigations.cfg, Some(true));
        assert_eq!(result.mitigations.high_entropy_va, Some(true));
        assert_eq!(
            result
                .mitigations
                .load_config
                .as_ref()
                .and_then(|config| config.guard_flags),
            Some(0x100)
        );
    }

    #[test]
    fn parses_bounded_relocation_blocks_and_unknown_types() {
        let mut bytes = fixture(0x014c, 0x10b);
        // PE32 relocation directory index 5 is at optional-header offset 136.
        bytes[0x98 + 96 + 40..0x98 + 96 + 44].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[0x98 + 96 + 44..0x98 + 96 + 48].copy_from_slice(&12u32.to_le_bytes());
        bytes[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x404..0x408].copy_from_slice(&12u32.to_le_bytes());
        bytes[0x408..0x40a].copy_from_slice(&0x3010u16.to_le_bytes());
        bytes[0x40a..0x40c].copy_from_slice(&0xa020u16.to_le_bytes());
        let result = inspect(&bytes).expect("valid PE");
        let block = &result.relocations.as_ref().unwrap().blocks[0];
        assert_eq!(block.page_rva, 0x1000);
        assert_eq!(block.entries[0].relocation_type, 3);
        assert_eq!(block.entries[0].rva, 0x1010);
        assert_eq!(block.entries[1].relocation_type, 10);
        assert!(block.entries[0].file_offset.is_some());
    }

    #[test]
    fn decodes_pe32_tls_callback_array_without_execution() {
        let mut bytes = fixture(0x014c, 0x10b);
        bytes[0xf4..0xf8].copy_from_slice(&10u32.to_le_bytes());
        bytes[0x98 + 28..0x98 + 32].copy_from_slice(&0x400000u32.to_le_bytes());
        bytes[0x98 + 96 + 72..0x98 + 96 + 76].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[0x98 + 96 + 76..0x98 + 96 + 80].copy_from_slice(&24u32.to_le_bytes());
        let tls_offset = 0x400;
        bytes[tls_offset + 12..tls_offset + 16].copy_from_slice(&0x401300u32.to_le_bytes());
        bytes[0x500..0x504].copy_from_slice(&0x401010u32.to_le_bytes());
        bytes[0x504..0x508].copy_from_slice(&0u32.to_le_bytes());
        let result = inspect(&bytes).expect("valid PE");
        let callback = &result.tls.as_ref().unwrap().callbacks[0];
        assert_eq!(result.tls.as_ref().unwrap().address_of_callbacks, 0x401300);
        assert_eq!(callback.virtual_address, 0x401010);
        assert_eq!(callback.rva, Some(0x1010));
        assert!(callback.file_offset.is_some());
    }

    #[test]
    fn decodes_delay_import_descriptor_without_execution() {
        let mut bytes = fixture(0x014c, 0x10b);
        bytes[0xf4..0xf8].copy_from_slice(&14u32.to_le_bytes());
        bytes[0x98 + 96 + 104..0x98 + 96 + 108].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[0x98 + 96 + 108..0x98 + 96 + 112].copy_from_slice(&32u32.to_le_bytes());
        bytes[0x400..0x404].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x404..0x408].copy_from_slice(&0x1500u32.to_le_bytes());
        bytes[0x700..0x70a].copy_from_slice(b"DELAY.dll\0");
        let result = inspect(&bytes).expect("valid PE");
        assert_eq!(
            result.delay_imports.as_ref().unwrap()[0].dll_name,
            "DELAY.dll"
        );
    }

    #[test]
    fn inventories_certificate_table_without_claiming_trust() {
        let mut bytes = fixture(0x014c, 0x10b);
        bytes[0x98 + 96 + 32..0x98 + 96 + 36].copy_from_slice(&0x600u32.to_le_bytes());
        bytes[0x98 + 96 + 36..0x98 + 96 + 40].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x600..0x604].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x604..0x606].copy_from_slice(&0x200u16.to_le_bytes());
        bytes[0x606..0x608].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x608..0x610].copy_from_slice(b"PKCS#7\0\0");
        let result = inspect(&bytes).expect("valid PE");
        let entry = &result.certificates.as_ref().unwrap().entries[0];
        assert_eq!(entry.revision, 0x200);
        assert_eq!(entry.certificate_type, 2);
        assert_eq!(entry.raw, b"PKCS#7\0\0");
        assert!(result.limitations.iter().any(|item| item.contains("trust")));
    }

    fn fixture(machine: u16, magic: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x2000];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0002u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&magic.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        let directory_offset = if magic == 0x20b { 112 } else { 96 };
        let count_offset = 0x98 + directory_offset - 4;
        bytes[count_offset..count_offset + 4].copy_from_slice(&7u32.to_le_bytes());
        let debug_entry = 0x98 + directory_offset + 6 * 8;
        bytes[debug_entry..debug_entry + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[debug_entry + 4..debug_entry + 8].copy_from_slice(&28u32.to_le_bytes());
        bytes[0x178..0x180].copy_from_slice(b".text\0\0\0");
        bytes[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x188..0x18c].copy_from_slice(&0x1800u32.to_le_bytes());
        bytes[0x18c..0x190].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x190..0x194].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x30c..0x310].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x310..0x314].copy_from_slice(&40u32.to_le_bytes());
        bytes[0x318..0x31c].copy_from_slice(&0x500u32.to_le_bytes());
        bytes
    }
}
