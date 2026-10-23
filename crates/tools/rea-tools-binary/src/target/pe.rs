//! MZ / PE / DOS-MZ header parsing without I/O, and the PE CodeView / managed
//! / COFF-machine helpers used by the I/O-driven `readPeMetadata` path.
//!
//! Ports:
//!   - `src/domain/dosMz.ts` (`observeMzWindowsHeader`, `parseDosMzHeader`,
//!     `dosMzImageByteLength`)
//!   - `src/domain/peMachine.ts` (`decodePeMachine`, `peOptionalHeaderMagic`)
//!   - the MZ branch of `src/domain/binaryTarget.ts` (`parseMz`,
//!     `parsePeRecord`, `parseCodeViewData`, `peDebugDirectoryEntry`,
//!     `peRvaToFileOffset`, `parsePeCodeViewFromBuffer`, `peManagedStatus`).

use serde_json::{Value, json};

use super::header::{ExecutableExtra, ExecutableMetadata, read_u16_le, read_u32_le};

// ----- peMachine.ts -----

/// `PeArchitecture` is `HeaderArchitecture` without hexagon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeMachine {
    pub architecture: &'static str,
    pub native_os_override: bool,
}

fn architecture_for_machine(machine: u16) -> Option<&'static str> {
    match machine {
        0x014c => Some("x86"),
        0x8664 => Some("x86_64"),
        0x01c0 | 0x01c2 | 0x01c4 => Some("arm"),
        0xaa64 => Some("arm64"),
        _ => None,
    }
}

/// TS `peOptionalHeaderMagic`.
fn pe_optional_header_magic(architecture: &str) -> u16 {
    if architecture == "x86_64" || architecture == "arm64" {
        0x20b
    } else {
        0x10b
    }
}

const NATIVE_OS_OVERRIDES: &[u16] = &[0x4644, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992];

/// TS `decodePeMachine`.
fn decode_pe_machine(machine: u16) -> Option<PeMachine> {
    if let Some(architecture) = architecture_for_machine(machine) {
        return Some(PeMachine {
            architecture,
            native_os_override: false,
        });
    }
    for override_value in NATIVE_OS_OVERRIDES {
        if let Some(architecture) = architecture_for_machine(machine ^ override_value) {
            return Some(PeMachine {
                architecture,
                native_os_override: true,
            });
        }
    }
    None
}

// ----- dosMz.ts -----

/// TS `MzWindowsHeaderObservation`.
#[derive(Clone, Debug)]
pub(crate) enum MzWindowsHeader {
    Absent,
    HeaderNeeded,
    SignatureNeeded { offset: u64 },
    Declared { offset: u64, signature: MzSignature },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MzSignature {
    Pe,
    Ne,
    Le,
    Lx,
    Other,
    Unobserved,
}

fn windows_header_signature(bytes: Option<&[u8]>) -> MzSignature {
    let bytes = match bytes {
        Some(bytes) if bytes.len() >= 2 => bytes,
        _ => return MzSignature::Unobserved,
    };
    let first = bytes[0];
    let second = bytes[1];
    if first == 0x4e && second == 0x45 {
        return MzSignature::Ne;
    }
    if first == 0x4c && second == 0x45 {
        return MzSignature::Le;
    }
    if first == 0x4c && second == 0x58 {
        return MzSignature::Lx;
    }
    if first != 0x50 || second != 0x45 {
        return MzSignature::Other;
    }
    if bytes.len() < 4 {
        return MzSignature::Unobserved;
    }
    if bytes[2] == 0 && bytes[3] == 0 {
        MzSignature::Pe
    } else {
        MzSignature::Other
    }
}

/// TS `observeMzWindowsHeader(bytes, fileSize, signatureAtOffset?)`.
pub(crate) fn observe_mz_windows_header(
    bytes: &[u8],
    file_size: u64,
    signature_at_offset: Option<&[u8]>,
) -> MzWindowsHeader {
    if bytes.len() < 64 {
        return if file_size >= 64 {
            MzWindowsHeader::HeaderNeeded
        } else {
            MzWindowsHeader::Absent
        };
    }
    let header_bytes = read_u16_le(bytes, 8) as u64 * 16;
    let relocation_count = read_u16_le(bytes, 6) as u64;
    let table_start = read_u16_le(bytes, 24) as u64;
    if header_bytes != 0
        && relocation_count > 0
        && table_start < 64
        && table_start + relocation_count * 4 > 60
    {
        return MzWindowsHeader::Absent;
    }
    let offset = read_u32_le(bytes, 60) as u64;
    if offset == 0 {
        return MzWindowsHeader::Absent;
    }
    let inline_signature: Option<&[u8]> = if offset < bytes.len() as u64 {
        let start = offset as usize;
        let end = std::cmp::min(start + 4, bytes.len());
        Some(&bytes[start..end])
    } else {
        None
    };
    let available = signature_at_offset.or(inline_signature);
    let signature = windows_header_signature(available);
    if header_bytes == 0 || header_bytes >= 64 {
        return MzWindowsHeader::Declared { offset, signature };
    }
    if signature != MzSignature::Other && signature != MzSignature::Unobserved {
        return MzWindowsHeader::Declared { offset, signature };
    }
    if signature == MzSignature::Other {
        return MzWindowsHeader::Absent;
    }
    let observed_pe_prefix = match available {
        Some(available) => available.len() >= 2 && available[0] == 0x50 && available[1] == 0x45,
        None => false,
    };
    // fileSize - offset < (observedPePrefix ? 4 : 2)
    let needed: u64 = if observed_pe_prefix { 4 } else { 2 };
    if file_size.saturating_sub(offset) < needed || file_size < offset + needed {
        return MzWindowsHeader::Absent;
    }
    MzWindowsHeader::SignatureNeeded { offset }
}

/// TS `dosMzImageByteLength(bytes)`.
fn dos_mz_image_byte_length(bytes: &[u8]) -> Result<u64, String> {
    if bytes.len() < 28 || &bytes[0..2] != b"MZ" {
        return Err("invalid or truncated DOS MZ header".to_string());
    }
    let last_page_bytes = read_u16_le(bytes, 2) as u64;
    let pages = read_u16_le(bytes, 4) as u64;
    if pages == 0 || last_page_bytes > 511 {
        return Err("invalid DOS MZ page count or final-page size".to_string());
    }
    Ok((pages - 1) * 512
        + if last_page_bytes == 0 {
            512
        } else {
            last_page_bytes
        })
}

/// TS `parseDosMzHeader(bytes, fileSize, signatureAtOffset?)` — validity only.
fn parse_dos_mz_header(
    bytes: &[u8],
    file_size: u64,
    signature_at_offset: Option<&[u8]>,
) -> Result<(), String> {
    if bytes.len() < 28 || &bytes[0..2] != b"MZ" {
        return Err("invalid or truncated DOS MZ header".to_string());
    }
    if file_size < bytes.len() as u64 {
        return Err("invalid DOS MZ file length".to_string());
    }
    let windows_header = observe_mz_windows_header(bytes, file_size, signature_at_offset);
    match windows_header {
        MzWindowsHeader::Declared { .. } => {
            return Err("MZ declares a Windows new header; it is not a DOS-only image".to_string());
        }
        MzWindowsHeader::SignatureNeeded { .. } => {
            return Err(
                "MZ Windows new-header signature is outside the bounded prefix".to_string(),
            );
        }
        _ => {}
    }
    let image_bytes = dos_mz_image_byte_length(bytes)?;
    let header_bytes = read_u16_le(bytes, 8) as u64 * 16;
    if header_bytes < 28 || header_bytes >= image_bytes {
        return Err("invalid DOS MZ header size or empty load module".to_string());
    }
    if image_bytes > file_size {
        return Err("truncated DOS MZ load module".to_string());
    }
    let relocation_count = read_u16_le(bytes, 6) as u64;
    let relocation_table_offset = read_u16_le(bytes, 24) as u64;
    let table_end = relocation_table_offset + relocation_count * 4;
    if relocation_count > 0 && (relocation_table_offset < 28 || table_end > header_bytes) {
        return Err("DOS MZ relocation table lies outside its header".to_string());
    }
    if relocation_count > 0 && table_end > bytes.len() as u64 {
        return Err("truncated DOS MZ relocation table".to_string());
    }
    if let MzWindowsHeader::HeaderNeeded = windows_header {
        return Err("MZ Windows new-header pointer is outside the bounded prefix".to_string());
    }
    let module_bytes = image_bytes - header_bytes;
    validate_relocations(
        bytes,
        relocation_table_offset,
        relocation_count,
        module_bytes,
    )?;
    let entry_offset = read_u16_le(bytes, 20) as u64;
    let entry_segment = read_u16_le(bytes, 22) as u64;
    if entry_segment * 16 + entry_offset >= module_bytes {
        return Err("DOS MZ entry point lies outside its initialized load module".to_string());
    }
    Ok(())
}

fn validate_relocations(
    bytes: &[u8],
    relocation_table_offset: u64,
    relocation_count: u64,
    module_bytes: u64,
) -> Result<(), String> {
    for index in 0..relocation_count {
        let record = (relocation_table_offset + index * 4) as usize;
        let offset = read_u16_le(bytes, record) as u64;
        let segment = read_u16_le(bytes, record + 2) as u64;
        if segment * 16 + offset + 2 > module_bytes {
            return Err(format!(
                "DOS MZ relocation {index} points outside its load module"
            ));
        }
    }
    Ok(())
}

// ----- binaryTarget.ts: parseMz / parsePeRecord and PE helpers -----

/// TS `parseMz(bytes, fileSize, signatureAtOffset?)`.
pub(crate) fn parse_mz(
    bytes: &[u8],
    file_size: u64,
    signature_at_offset: Option<&[u8]>,
) -> Result<ExecutableMetadata, String> {
    let windows_header = observe_mz_windows_header(bytes, file_size, signature_at_offset);
    match windows_header {
        MzWindowsHeader::HeaderNeeded | MzWindowsHeader::SignatureNeeded { .. } => {
            return Err(
                "Windows new-header pointer or signature is outside the bounded prefix".to_string(),
            );
        }
        MzWindowsHeader::Declared { offset, signature } => {
            if offset < 64 || offset > bytes.len() as u64 - 24 {
                return Err(
                    "invalid or truncated Windows executable header in MZ image".to_string()
                );
            }
            match signature {
                MzSignature::Ne => {
                    return Err("unsupported NE executable in MZ image".to_string());
                }
                MzSignature::Le => {
                    return Err("unsupported LE executable in MZ image".to_string());
                }
                MzSignature::Lx => {
                    return Err("unsupported LX executable in MZ image".to_string());
                }
                MzSignature::Pe => {}
                _ => {
                    return Err(
                        "invalid or truncated Windows executable header in MZ image".to_string()
                    );
                }
            }
            let code_view = parse_pe_code_view_from_buffer(bytes, offset as usize);
            return parse_pe_record(&bytes[offset as usize..], code_view);
        }
        MzWindowsHeader::Absent => {}
    }
    parse_dos_mz_header(bytes, file_size, signature_at_offset)?;
    Ok(ExecutableMetadata {
        format: "dos-mz",
        architecture: "x86".to_string(),
        available_architectures: vec!["x86".to_string()],
        extra: ExecutableExtra::None,
    })
}

/// TS `parsePeRecord(record, codeView)`.
pub(crate) fn parse_pe_record(
    record: &[u8],
    code_view: Option<Value>,
) -> Result<ExecutableMetadata, String> {
    if record.len() < 24 || &record[0..4] != b"PE\0\0" {
        return Err("invalid or truncated PE header".to_string());
    }
    let machine_type = read_u16_le(record, 4);
    let machine = match decode_pe_machine(machine_type) {
        Some(machine) => machine,
        None => {
            return Err(format!(
                "unsupported PE architecture (COFF machine 0x{machine_type:04x})"
            ));
        }
    };
    let architecture = machine.architecture;
    let optional_header_size = read_u16_le(record, 20) as usize;
    if optional_header_size > 4096 || record.len() < 24 + optional_header_size {
        return Err("invalid or truncated PE optional header".to_string());
    }
    let optional_header = &record[24..24 + optional_header_size];
    let managed = pe_managed_status(optional_header, architecture)?;
    if machine.native_os_override && !managed {
        return Err("unsupported PE architecture".to_string());
    }
    let characteristics = read_u16_le(record, 22);
    let executable_role = if characteristics & 0x0002 == 0 {
        "non-executable"
    } else if characteristics & 0x2000 == 0 {
        "application"
    } else {
        "shared-library"
    };
    Ok(ExecutableMetadata {
        format: "pe",
        architecture: architecture.to_string(),
        available_architectures: vec![architecture.to_string()],
        extra: ExecutableExtra::Pe {
            pe_machine: machine_type as u32,
            executable_role,
            managed,
            code_view,
        },
    })
}

/// TS `peManagedStatus(optionalHeader, architecture)`.
fn pe_managed_status(optional_header: &[u8], architecture: &str) -> Result<bool, String> {
    if optional_header.len() < 2 {
        return Err("truncated PE optional header".to_string());
    }
    let magic = read_u16_le(optional_header, 0);
    if magic != pe_optional_header_magic(architecture) {
        return Err("PE optional-header magic does not match its architecture".to_string());
    }
    let directory_offset: usize = if magic == 0x20b { 112 } else { 96 };
    let directory_count_offset = directory_offset - 4;
    if optional_header.len() < directory_count_offset + 4 {
        return Err("truncated PE optional header".to_string());
    }
    let directory_count = read_u32_le(optional_header, directory_count_offset) as u64;
    let required_bytes = directory_offset as u64 + directory_count * 8;
    // Number.isSafeInteger(requiredBytes): bounded well below 2^53 here.
    if required_bytes > optional_header.len() as u64 {
        return Err("truncated PE data-directory table".to_string());
    }
    if directory_count <= 14 {
        return Ok(false);
    }
    let cli_directory = directory_offset + 14 * 8;
    Ok(read_u32_le(optional_header, cli_directory) != 0
        || read_u32_le(optional_header, cli_directory + 4) != 0)
}

/// TS `peDebugDirectoryEntry(optionalHeader)`.
pub(crate) struct PeDebugDirectory {
    pub debug_rva: u32,
    pub debug_size: u32,
    pub size_of_headers: u32,
}

pub(crate) fn pe_debug_directory_entry(optional_header: &[u8]) -> Option<PeDebugDirectory> {
    if optional_header.len() < 2 {
        return None;
    }
    let magic = read_u16_le(optional_header, 0);
    if magic != 0x10b && magic != 0x20b {
        return None;
    }
    let directory_offset: usize = if magic == 0x20b { 112 } else { 96 };
    let directory_count_offset = directory_offset - 4;
    if optional_header.len() < directory_count_offset + 4 {
        return None;
    }
    let directory_count = read_u32_le(optional_header, directory_count_offset);
    if directory_count <= 6 {
        return None;
    }
    let debug_entry_offset = directory_offset + 6 * 8;
    if optional_header.len() < debug_entry_offset + 8 {
        return None;
    }
    let debug_rva = read_u32_le(optional_header, debug_entry_offset);
    let debug_size = read_u32_le(optional_header, debug_entry_offset + 4);
    if debug_rva == 0 || debug_size < 28 {
        return None;
    }
    Some(PeDebugDirectory {
        debug_rva,
        debug_size,
        size_of_headers: read_u32_le(optional_header, 60),
    })
}

/// TS `peRvaToFileOffset(rva, sectionTable, numberOfSections, sizeOfHeaders, size=1)`.
pub(crate) fn pe_rva_to_file_offset(
    rva: u32,
    section_table: &[u8],
    number_of_sections: u32,
    size_of_headers: u32,
    size: u32,
) -> Option<u32> {
    if rva < size_of_headers && size <= size_of_headers - rva {
        return Some(rva);
    }
    for index in 0..number_of_sections as usize {
        let offset = index * 40;
        if section_table.len() < offset + 40 {
            break;
        }
        let virtual_address = read_u32_le(section_table, offset + 12);
        let size_of_raw_data = read_u32_le(section_table, offset + 16);
        let pointer_to_raw_data = read_u32_le(section_table, offset + 20);
        if pointer_to_raw_data > 0
            && rva >= virtual_address
            && rva - virtual_address < size_of_raw_data
            && size <= size_of_raw_data - (rva - virtual_address)
        {
            return Some(pointer_to_raw_data + (rva - virtual_address));
        }
    }
    None
}

/// TS `parseCodeViewData(buffer, sizeOfData)`.
pub(crate) fn parse_code_view_data(buffer: &[u8], size_of_data: u32) -> Option<Value> {
    if size_of_data < 16 || buffer.len() < 16 {
        return None;
    }
    let magic = &buffer[0..4];
    let path_offset: usize = if magic == b"RSDS" {
        24
    } else if magic == b"NB10" {
        16
    } else {
        return None;
    };
    if (size_of_data as usize) <= path_offset || buffer.len() <= path_offset {
        return None;
    }
    let end = buffer[path_offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| position + path_offset);
    let end = match end {
        Some(end) => end,
        None => return None, // indexOf returns -1 -> end <= pathOffset is false but no NUL
    };
    if end <= path_offset || end >= size_of_data as usize {
        return None;
    }
    let pdb_path = String::from_utf8_lossy(&buffer[path_offset..end]).into_owned();
    let pdb_file_name = pdb_path
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(&pdb_path)
        .to_string();
    if magic == b"RSDS" && size_of_data >= 24 && buffer.len() >= 24 {
        let part1 = format!("{:08x}", read_u32_le(buffer, 4));
        let part2 = format!("{:04x}", read_u16_le(buffer, 8));
        let part3 = format!("{:04x}", read_u16_le(buffer, 10));
        let part4 = hex(&buffer[12..14]);
        let part5 = hex(&buffer[14..20]);
        let guid = format!("{part1}-{part2}-{part3}-{part4}-{part5}");
        let age = read_u32_le(buffer, 20);
        return Some(json!({
            "pdbPath": pdb_path,
            "pdbFileName": pdb_file_name,
            "guid": guid,
            "age": age,
        }));
    }
    if magic == b"NB10" {
        let age = read_u32_le(buffer, 12);
        return Some(json!({
            "pdbPath": pdb_path,
            "pdbFileName": pdb_file_name,
            "guid": Value::Null,
            "age": age,
        }));
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// TS `parsePeCodeViewFromBuffer(fileBytes, peOffset)`.
pub(crate) fn parse_pe_code_view_from_buffer(file_bytes: &[u8], pe_offset: usize) -> Option<Value> {
    if file_bytes.len() < pe_offset + 24 {
        return None;
    }
    let number_of_sections = read_u16_le(file_bytes, pe_offset + 6) as u32;
    let optional_header_size = read_u16_le(file_bytes, pe_offset + 20) as usize;
    if optional_header_size > 4096 || file_bytes.len() < pe_offset + 24 + optional_header_size {
        return None;
    }
    let optional_header = &file_bytes[pe_offset + 24..pe_offset + 24 + optional_header_size];
    let debug_dir = pe_debug_directory_entry(optional_header)?;
    let section_table_offset = pe_offset + 24 + optional_header_size;
    let section_table_size = number_of_sections as usize * 40;
    if file_bytes.len() < section_table_offset + section_table_size {
        return None;
    }
    let section_table =
        &file_bytes[section_table_offset..section_table_offset + section_table_size];
    let debug_file_offset = pe_rva_to_file_offset(
        debug_dir.debug_rva,
        section_table,
        number_of_sections,
        debug_dir.size_of_headers,
        std::cmp::min(debug_dir.debug_size, 4096),
    )?;
    let debug_file_offset = debug_file_offset as usize;
    if file_bytes.len() < debug_file_offset + 28 {
        return None;
    }
    let max_debug_bytes = std::cmp::min(
        debug_dir.debug_size as usize,
        file_bytes.len() - debug_file_offset,
    );
    let num_entries = max_debug_bytes / 28;
    for j in 0..num_entries {
        let entry_offset = debug_file_offset + j * 28;
        let entry_type = read_u32_le(file_bytes, entry_offset + 12);
        if entry_type != 2 {
            continue; // IMAGE_DEBUG_TYPE_CODEVIEW
        }
        let size_of_data = read_u32_le(file_bytes, entry_offset + 16);
        let mut pointer_to_raw_data = read_u32_le(file_bytes, entry_offset + 24);
        if pointer_to_raw_data == 0 {
            let address_of_raw_data = read_u32_le(file_bytes, entry_offset + 20);
            let mapped = pe_rva_to_file_offset(
                address_of_raw_data,
                section_table,
                number_of_sections,
                debug_dir.size_of_headers,
                std::cmp::min(size_of_data, 4096),
            );
            match mapped {
                Some(mapped) => pointer_to_raw_data = mapped,
                None => continue,
            }
        }
        let pointer = pointer_to_raw_data as usize;
        if size_of_data < 16
            || file_bytes.len() < pointer + std::cmp::min(size_of_data as usize, 24)
        {
            continue;
        }
        let end = std::cmp::min(file_bytes.len(), pointer + size_of_data as usize);
        let code_view_data = &file_bytes[pointer..end];
        if let Some(parsed) = parse_code_view_data(code_view_data, size_of_data) {
            return Some(parsed);
        }
    }
    None
}
