//! Bounded PE COFF/optional-header parsing used by desktop byte probing.
//!
//! Ports the managed-status subset of `parsePeRecord`, `decodePeMachine`,
//! `peOptionalHeaderMagic` and `peRvaToFileOffset` from
//! `src/domain/binaryTarget.ts`, `src/domain/peMachine.ts`. No I/O.

/// A decoded COFF machine and whether it carried a ReadyToRun OS override.
pub(crate) struct PeMachine {
    pub architecture: PeArchitecture,
    pub native_os_override: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeArchitecture {
    X86,
    X86_64,
    Arm,
    Arm64,
}

fn architecture_for_machine(machine: u16) -> Option<PeArchitecture> {
    match machine {
        0x014c => Some(PeArchitecture::X86),
        0x8664 => Some(PeArchitecture::X86_64),
        0x01c0 | 0x01c2 | 0x01c4 => Some(PeArchitecture::Arm),
        0xaa64 => Some(PeArchitecture::Arm64),
        _ => None,
    }
}

/// The optional-header magic a machine's architecture requires.
fn pe_optional_header_magic(architecture: PeArchitecture) -> u16 {
    match architecture {
        PeArchitecture::X86_64 | PeArchitecture::Arm64 => 0x20b,
        _ => 0x10b,
    }
}

/// ReadyToRun OS overrides (dotnet/runtime pedecoder.h).
const NATIVE_OS_OVERRIDES: [u16; 6] = [0x4644, 0xadc4, 0xadc5, 0x7b79, 0x1993, 0x1992];

/// Decode a COFF machine; only managed images may carry an OS override.
fn decode_pe_machine(machine: u16) -> Option<PeMachine> {
    if let Some(direct) = architecture_for_machine(machine) {
        return Some(PeMachine {
            architecture: direct,
            native_os_override: false,
        });
    }
    for over in NATIVE_OS_OVERRIDES {
        if let Some(architecture) = architecture_for_machine(machine ^ over) {
            return Some(PeMachine {
                architecture,
                native_os_override: true,
            });
        }
    }
    None
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// The managed status of a PE optional header (`peManagedStatus`).
fn pe_managed_status(optional_header: &[u8], architecture: PeArchitecture) -> Result<bool, String> {
    if optional_header.len() < 2 {
        return Err("truncated PE optional header".into());
    }
    let magic = read_u16(optional_header, 0).unwrap();
    if magic != pe_optional_header_magic(architecture) {
        return Err("PE optional-header magic does not match its architecture".into());
    }
    let directory_offset: usize = if magic == 0x20b { 112 } else { 96 };
    let directory_count_offset = directory_offset - 4;
    if optional_header.len() < directory_count_offset + 4 {
        return Err("truncated PE optional header".into());
    }
    let directory_count = read_u32(optional_header, directory_count_offset).unwrap() as usize;
    let required_bytes = directory_offset + directory_count * 8;
    if required_bytes > optional_header.len() {
        return Err("truncated PE data-directory table".into());
    }
    if directory_count <= 14 {
        return Ok(false);
    }
    let cli_directory = directory_offset + 14 * 8;
    Ok(read_u32(optional_header, cli_directory).unwrap_or(0) != 0
        || read_u32(optional_header, cli_directory + 4).unwrap_or(0) != 0)
}

/// Parse result of a PE COFF/optional-header record (`parsePeRecord` subset).
pub(crate) struct PeRecord {
    /// `format === "pe"` always holds for a successful parse here.
    pub managed: bool,
}

/// Parse a bounded PE signature, COFF record and optional header (no I/O).
/// `record` is the concatenation of the 24-byte COFF record and the optional
/// header (exactly as the TS caller passes `Buffer.concat([coff, optional])`).
pub(crate) fn parse_pe_record(record: &[u8]) -> Result<PeRecord, String> {
    if record.len() < 24 || &record[0..4] != b"PE\0\0" {
        return Err("invalid or truncated PE header".into());
    }
    let machine_type = read_u16(record, 4).unwrap();
    let machine = decode_pe_machine(machine_type).ok_or_else(|| {
        format!("unsupported PE architecture (COFF machine 0x{machine_type:04x})")
    })?;
    let architecture = machine.architecture;
    let optional_header_size = read_u16(record, 20).unwrap() as usize;
    if optional_header_size > 4096 || record.len() < 24 + optional_header_size {
        return Err("invalid or truncated PE optional header".into());
    }
    let optional_header = &record[24..24 + optional_header_size];
    let managed = pe_managed_status(optional_header, architecture)?;
    if machine.native_os_override && !managed {
        return Err("unsupported PE architecture".into());
    }
    Ok(PeRecord { managed })
}

/// Translate an RVA to an absolute file offset using a raw section table
/// (`peRvaToFileOffset`). `section_table` is `number_of_sections * 40` bytes.
pub(crate) fn pe_rva_to_file_offset(
    rva: u32,
    section_table: &[u8],
    number_of_sections: u16,
    size_of_headers: u32,
    size: u32,
) -> Option<usize> {
    if rva < size_of_headers && size <= size_of_headers - rva {
        return Some(rva as usize);
    }
    for index in 0..number_of_sections as usize {
        let offset = index * 40;
        if section_table.len() < offset + 40 {
            break;
        }
        let virtual_address = read_u32(section_table, offset + 12)?;
        let size_of_raw_data = read_u32(section_table, offset + 16)?;
        let pointer_to_raw_data = read_u32(section_table, offset + 20)?;
        if pointer_to_raw_data > 0
            && rva >= virtual_address
            && rva - virtual_address < size_of_raw_data
            && size <= size_of_raw_data - (rva - virtual_address)
        {
            return Some((pointer_to_raw_data + (rva - virtual_address)) as usize);
        }
    }
    None
}
