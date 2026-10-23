//! Bounded ELF64 layout extraction for the native `inspect_binary_layout` contract.
//!
//! This reader deliberately operates on an already admitted snapshot. It never opens,
//! executes, or resolves a target path, so Evidence ownership remains in the application
//! layer.
use serde::Serialize;
use std::fmt;

const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    InputLimit,
    Format(&'static str),
    Message(String),
    Unsupported(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimit => f.write_str("selected ELF exceeds 256 MiB"),
            Self::Format(s) => f.write_str(s),
            Self::Message(s) => f.write_str(s),
            Self::Unsupported(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Serialize)]
pub struct Layout {
    pub format: &'static str,
    pub architecture: Architecture,
    pub image_type: String,
    pub entry_point: EntryPoint,
    pub runtime_load_base: Option<()>,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub packed_relative_relocations: Vec<PackedRelocation>,
    pub relocation_inventory_completeness: &'static str,
    pub linkage: Linkage,
    pub mitigations: Mitigations,
    pub notes: Vec<Note>,
    pub debug_links: Vec<DebugLink>,
    pub section_groups: Vec<SectionGroup>,
    pub extended_numbering: Option<ExtendedNumbering>,
    pub stack_policy: Option<StackPolicy>,
    pub relro_policy: Option<RelroPolicy>,
    pub tls_segments: Vec<TlsSegment>,
    pub eh_frame_segments: Vec<EhFrameSegment>,
    pub dynamic_flags: Option<DynamicFlags>,
    pub dynamic_string_tags: Option<Vec<DynamicStringTag>>,
    pub dynamic_gnu_hash: Option<DynamicGnuHash>,
    pub symbol_version_tables: Option<SymbolVersionTables>,
}
#[derive(Debug, Serialize)]
pub struct Note {
    pub segment_index: usize,
    pub name: String,
    pub note_type: u32,
    pub descriptor_base64: String,
    pub location: Range,
    pub malformed: bool,
    pub decoded: Option<DecodedNote>,
}
#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum DecodedNote {
    #[serde(rename = "gnu-build-id")]
    GnuBuildId { build_id_base64: String },
    #[serde(rename = "gnu-abi-tag")]
    GnuAbiTag {
        os: String,
        major: String,
        minor: String,
        subminor: String,
        malformed: bool,
    },
    #[serde(rename = "gnu-property")]
    GnuProperty {
        properties: Vec<GnuPropertyValue>,
        malformed: bool,
    },
    #[serde(rename = "nt-file")]
    NtFile {
        page_size: u64,
        mappings: Vec<CoreFileMapping>,
        malformed: bool,
    },
    #[serde(rename = "nt-prstatus")]
    NtPrStatus {
        signal: Option<u64>,
        pid: Option<u64>,
        ppid: Option<u64>,
        tid: Option<u64>,
        malformed: bool,
    },
    #[serde(rename = "nt-auxv")]
    NtAuxv {
        entries: Vec<CoreAuxvEntry>,
        malformed: bool,
    },
    #[serde(rename = "nt-siginfo")]
    NtSigInfo {
        signal: Option<i64>,
        errno: Option<i64>,
        code: Option<i64>,
        malformed: bool,
    },
    #[serde(rename = "nt-fpregset")]
    NtFpRegSet { byte_length: u64, malformed: bool },
    #[serde(rename = "nt-prpsinfo")]
    NtPrPsInfo {
        pid: Option<i64>,
        command: Option<String>,
        malformed: bool,
    },
    #[serde(rename = "nt-taskstruct")]
    NtTaskStruct { byte_length: u64, malformed: bool },
}
#[derive(Debug, Serialize)]
pub struct GnuPropertyValue {
    pub property_type: u32,
    pub data_base64: String,
    pub named_bits: Vec<String>,
    pub unknown_bits: Vec<String>,
    pub descriptor_offset: String,
    pub location: Range,
    pub malformed: bool,
}
#[derive(Debug, Serialize)]
pub struct CoreFileMapping {
    pub start: String,
    pub end: String,
    pub file_offset: String,
    pub path: String,
}
#[derive(Debug, Serialize)]
pub struct CoreAuxvEntry {
    pub kind: String,
    pub value: String,
}
#[derive(Debug, Serialize)]
pub struct DebugLink {
    pub kind: &'static str,
    pub filename: String,
    pub filename_base64: String,
    pub crc32: Option<String>,
    pub crc32_location: Option<Range>,
    pub build_id_base64: Option<String>,
    pub build_id_location: Option<Range>,
    pub location: Range,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct PeDebugDirectoryEntry {
    pub index: usize,
    pub debug_type: &'static str,
    pub raw_type: String,
    pub timestamp: String,
    pub major_version: u16,
    pub minor_version: u16,
    pub size_of_data: String,
    pub data_rva: String,
    pub file_pointer: String,
    pub directory_location: Option<Range>,
    pub data_location: Option<Range>,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct PeCertificateTable {
    pub file_offset: String,
    pub declared_size: String,
    pub observed_size: String,
    pub location: Option<Range>,
    pub entries: Vec<PeCertificateEntry>,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct PeCertificateEntry {
    pub location: Range,
    pub length: String,
    pub revision: u16,
    pub certificate_type: u16,
    pub certificate_type_name: &'static str,
    pub raw_base64: String,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct PeHeaderMetadata {
    pub machine: String,
    pub section_count: usize,
    pub coff_characteristics: String,
    pub optional_magic: String,
    pub image_base: String,
    pub entry_point_rva: String,
    pub size_of_image: String,
    pub size_of_headers: String,
    pub subsystem: u16,
    pub dll_characteristics: String,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct PeResourceEntry {
    pub path: Vec<String>,
    pub directory_location: Range,
    pub data_location: Option<Range>,
    pub data_rva: String,
    pub data_size: String,
    pub code_page: u32,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct SectionGroup {
    pub section_index: usize,
    pub flags: String,
    pub signature_symbol_table: usize,
    pub signature_symbol_index: usize,
    pub signature_name: Option<Name>,
    pub member_section_indices: Vec<usize>,
    pub location: Range,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct ExtendedNumbering {
    pub section_count: Option<u64>,
    pub program_count: Option<u64>,
    pub section_name_index: Option<u64>,
    pub section_zero_location: Range,
}
#[derive(Debug, Serialize)]
pub struct Architecture {
    pub machine: String,
    pub bits: u8,
    pub byte_order: String,
}
#[derive(Debug, Serialize)]
pub struct EntryPoint {
    pub reported_value: String,
    pub meaning: &'static str,
    pub execution_status: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct Range {
    pub offset: String,
    pub bytes: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Name {
    pub display: String,
    pub bytes_base64: Option<String>,
    pub location: Option<Range>,
    pub unknown_reason: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Section {
    pub index: usize,
    pub name: Name,
    pub name_offset: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub header_location: Range,
    pub address: String,
    pub offset: String,
    pub size: String,
    pub alignment: String,
    pub flags: String,
    pub link: usize,
    pub info: usize,
    pub entry_size: String,
    pub file_backing: &'static str,
    pub compression: Option<CompressionInfo>,
}
#[derive(Debug, Serialize)]
pub struct CompressionInfo {
    pub algorithm: String,
    pub raw_algorithm: String,
    pub declared_uncompressed_size: String,
    pub declared_alignment: String,
    pub header_location: Range,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
#[derive(Debug, Serialize)]
pub struct Segment {
    pub index: usize,
    #[serde(rename = "type")]
    pub kind: String,
    pub header_location: Range,
    pub offset: String,
    pub file_size: String,
    pub memory_size: String,
    pub virtual_address: String,
    pub physical_address: String,
    pub alignment: String,
    pub flags: String,
    pub file_backing: &'static str,
    pub permissions: Option<Permissions>,
}
#[derive(Debug, Serialize)]
pub struct StackPolicy {
    pub segment_index: usize,
    pub flags: String,
    pub policy: &'static str,
    pub header_location: Range,
    pub duplicate: bool,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct RelroPolicy {
    pub segment_index: usize,
    pub file_offset: String,
    pub file_size: String,
    pub virtual_address: String,
    pub memory_size: String,
    pub flags: String,
    pub header_location: Range,
    pub source_location: Option<Range>,
    pub policy: &'static str,
    pub duplicate: bool,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct TlsSegment {
    pub segment_index: usize,
    pub file_offset: String,
    pub file_size: String,
    pub virtual_address: String,
    pub memory_size: String,
    pub alignment: String,
    pub flags: String,
    pub header_location: Range,
    pub source_location: Option<Range>,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct EhFrameSegment {
    pub segment_index: usize,
    pub file_offset: String,
    pub file_size: String,
    pub virtual_address: String,
    pub memory_size: String,
    pub alignment: String,
    pub flags: String,
    pub source_location: Option<Range>,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct DynamicFlags {
    pub entries: Vec<DynamicFlagEntry>,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct DynamicFlagEntry {
    pub tag: String,
    pub value: String,
    pub named_bits: Vec<String>,
    pub unknown_bits: Vec<String>,
    pub location: Range,
}
#[derive(Debug, Serialize)]
pub struct DynamicStringTag {
    pub tag: String,
    pub tag_name: &'static str,
    pub string_offset: String,
    pub value: Option<String>,
    pub string_location: Option<Range>,
    pub entry_location: Range,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct DynamicGnuHash {
    pub location: Option<Range>,
    pub bucket_count: Option<u32>,
    pub symbol_offset: Option<u32>,
    pub bloom_word_count: Option<u32>,
    pub bloom_shift: Option<u32>,
    pub bloom_location: Option<Range>,
    pub bucket_location: Option<Range>,
    pub chain_location: Option<Range>,
    pub symbol_count: Option<u64>,
    pub malformed: bool,
    pub unknown_reason: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct SymbolVersionTables {
    pub definitions: Vec<SymbolVersionDefinition>,
    pub requirements: Vec<SymbolVersionRequirement>,
    pub malformed: bool,
}
#[derive(Debug, Serialize)]
pub struct SymbolVersionDefinition {
    pub index: u16,
    pub flags: u16,
    pub auxiliary_names: Vec<String>,
    pub location: Range,
    pub malformed: bool,
}
#[derive(Debug, Serialize)]
pub struct SymbolVersionRequirement {
    pub file: Option<String>,
    pub auxiliary_names: Vec<String>,
    pub location: Range,
    pub malformed: bool,
}
#[derive(Debug, Serialize)]
pub struct Symbol {
    pub table_index: usize,
    pub entry_index: usize,
    pub name: Name,
    pub name_offset: String,
    pub location: Range,
    pub value: String,
    pub value_meaning: &'static str,
    pub size: String,
    pub binding: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub visibility: String,
    pub section_index: String,
    pub reported_section_index: String,
    pub version: Option<String>,
    /// Raw GNU version-table value, including the hidden bit when present.
    pub version_index: Option<u16>,
    /// File range of the associated versym entry when it was readable.
    pub version_location: Option<Range>,
    /// `unknown`, `unversioned`, `resolved`, or `unresolved`.
    pub version_state: &'static str,
    pub version_hidden: bool,
}
#[derive(Debug, Serialize)]
pub struct Relocation {
    pub section_index: usize,
    pub entry_index: usize,
    pub reported_offset: String,
    pub target: RelocationTarget,
    pub location: Range,
    #[serde(rename = "type")]
    pub kind: usize,
    pub symbol_table_index: usize,
    pub symbol_index: usize,
    pub symbol_reference_meaning: &'static str,
    pub addend: Option<String>,
    pub symbol: Option<Name>,
    pub symbol_version: Option<String>,
    pub symbol_version_hidden: bool,
    pub symbol_resolution: &'static str,
}
#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum RelocationTarget {
    #[serde(rename = "section-offset")]
    SectionOffset {
        section_index: usize,
        offset: String,
    },
    #[serde(rename = "linked-virtual-address")]
    LinkedVirtualAddress { address: String },
    #[serde(rename = "unknown-section")]
    UnknownSection {
        reported_section_index: usize,
        offset: String,
        unknown_reason: &'static str,
    },
}
#[derive(Debug, Serialize)]
pub struct PackedRelocation {
    pub section_index: usize,
    pub location: Range,
    pub encoded_bytes_base64: String,
    pub entries: Vec<PackedEntry>,
    pub offset_meaning: &'static str,
    pub evidence_kind: &'static str,
    pub entry_source_locations: Option<()>,
    pub addends: Option<()>,
}
#[derive(Debug, Serialize)]
pub struct PackedEntry {
    pub decoded_index: usize,
    pub reported_offset: String,
}
#[derive(Debug, Serialize)]
pub struct Linkage {
    pub needed_libraries: Vec<Name>,
    pub interpreters: Vec<Name>,
    pub got: Vec<LinkedName>,
    pub plt: Vec<LinkedName>,
    pub convenience_maps_completeness: &'static str,
    pub runtime_library_paths: Option<()>,
}
#[derive(Debug, Serialize)]
pub struct LinkedName {
    pub display_name: String,
    pub address: String,
}
#[derive(Debug, Serialize)]
pub struct Mitigations {
    pub evidence_kind: &'static str,
    pub position_independent: bool,
    pub nx_indicator: Option<bool>,
    pub executable_stack_indicator: bool,
    pub stack_canary_indicator: bool,
    pub relro: Option<String>,
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}
fn checked_range(bytes: &[u8], offset: u64, size: u64) -> Result<Range, Error> {
    let end = offset
        .checked_add(size)
        .ok_or(Error::Format("ELF range overflowed"))?;
    if end > bytes.len() as u64 {
        return Err(Error::Format(
            "ELF contains a file-backed range outside the selected snapshot.",
        ));
    }
    Ok(Range {
        offset: hex(offset),
        bytes: hex(size),
    })
}

const MAX_PE_DEBUG_DIRECTORY_BYTES: usize = 4096;
const PE_DEBUG_DIRECTORY_ENTRY_BYTES: usize = 28;

/// Project the bounded PE debug directory without reading or resolving companion files.
///
/// The returned records retain the raw directory values even when an RVA or file
/// pointer cannot be mapped into the admitted snapshot. This keeps malformed input
/// distinguishable from an absent debug directory.
pub fn parse_pe_debug_directory(bytes: &[u8]) -> Result<Vec<PeDebugDirectoryEntry>, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }

    let pe_offset = pe_header_offset(bytes)?;
    let (optional_offset, optional_size, section_count) = pe_headers(bytes, pe_offset)?;
    let (debug_rva, debug_size, size_of_headers) =
        pe_debug_data(bytes, optional_offset, optional_size)?;
    if debug_rva == 0 || debug_size < PE_DEBUG_DIRECTORY_ENTRY_BYTES as u32 {
        return Ok(Vec::new());
    }

    let sections = pe_sections(bytes, optional_offset, optional_size, section_count)?;
    let admitted_size = (debug_size as usize).min(MAX_PE_DEBUG_DIRECTORY_BYTES);
    let Some(debug_offset) = pe_rva_to_file_offset(
        debug_rva,
        admitted_size,
        size_of_headers,
        &sections,
        bytes.len(),
    ) else {
        return Ok(vec![malformed_pe_debug_entry(
            0,
            None,
            debug_size,
            debug_rva,
            0,
            "debug-directory-range-outside-snapshot",
        )]);
    };

    let debug_end = debug_offset
        .checked_add(admitted_size)
        .ok_or(Error::Format("PE debug directory range overflowed"))?;
    let debug_bytes = &bytes[debug_offset..debug_end];
    let complete_entries = debug_bytes.len() / PE_DEBUG_DIRECTORY_ENTRY_BYTES;
    let mut entries =
        Vec::with_capacity(complete_entries + usize::from(debug_bytes.len() % 28 != 0));
    for index in 0..complete_entries {
        entries.push(parse_pe_debug_entry(
            index,
            debug_bytes,
            debug_offset,
            size_of_headers,
            &sections,
            bytes.len(),
        )?);
    }
    if debug_bytes.len() % PE_DEBUG_DIRECTORY_ENTRY_BYTES != 0 {
        entries.push(malformed_pe_debug_entry(
            complete_entries,
            Some(Range {
                offset: hex(
                    (debug_offset + complete_entries * PE_DEBUG_DIRECTORY_ENTRY_BYTES) as u64,
                ),
                bytes: hex((debug_bytes.len() % PE_DEBUG_DIRECTORY_ENTRY_BYTES) as u64),
            }),
            debug_size,
            debug_rva,
            0,
            "truncated-debug-directory-entry",
        ));
    }
    Ok(entries)
}

/// Read the PE security directory as bounded observed metadata. Certificate
/// payloads are retained as bytes for provenance; no trust or signature claim
/// is made from their contents.
pub fn parse_pe_certificate_table(bytes: &[u8]) -> Result<Option<PeCertificateTable>, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }
    let pe_offset = pe_header_offset(bytes)?;
    let (optional_offset, optional_size, _) = pe_headers(bytes, pe_offset)?;
    let Some((file_offset, declared_size)) =
        pe_data_directory(bytes, optional_offset, optional_size, 4)?
    else {
        return Ok(None);
    };
    if declared_size == 0 {
        return Ok(None);
    }

    const MAX_CERTIFICATE_BYTES: usize = MAX_PE_DEBUG_DIRECTORY_BYTES * 16;
    let bounded_size = (declared_size as usize).min(MAX_CERTIFICATE_BYTES);
    let Some(observed_end) = (file_offset as usize).checked_add(bounded_size) else {
        return Ok(Some(malformed_pe_certificate_table(
            file_offset,
            declared_size,
            "certificate-table-range-overflow",
        )));
    };
    let observed_end = observed_end.min(bytes.len());
    let start = file_offset as usize;
    if start >= observed_end || start % 8 != 0 {
        return Ok(Some(malformed_pe_certificate_table(
            file_offset,
            declared_size,
            "certificate-table-range-outside-snapshot-or-misaligned",
        )));
    }

    let table_bytes = &bytes[start..observed_end];
    let mut cursor = 0usize;
    let mut entries = Vec::new();
    let mut malformed = declared_size as usize > MAX_CERTIFICATE_BYTES
        || observed_end - start < declared_size as usize;
    let mut unknown_reason = if malformed {
        Some("certificate-table-truncated-or-resource-bounded")
    } else {
        None
    };
    while cursor < table_bytes.len() && entries.len() < 4096 {
        let remaining = table_bytes.len() - cursor;
        if remaining < 8 {
            malformed = true;
            unknown_reason = Some("truncated-certificate-entry-header");
            break;
        }
        let length = u32::from_le_bytes(table_bytes[cursor..cursor + 4].try_into().unwrap());
        let revision = u16::from_le_bytes(table_bytes[cursor + 4..cursor + 6].try_into().unwrap());
        let certificate_type =
            u16::from_le_bytes(table_bytes[cursor + 6..cursor + 8].try_into().unwrap());
        if length < 8 || length as usize > remaining {
            malformed = true;
            unknown_reason = Some("invalid-certificate-entry-length");
            break;
        }
        let entry_length = length as usize;
        let raw = &table_bytes[cursor + 8..cursor + entry_length];
        entries.push(PeCertificateEntry {
            location: Range {
                offset: hex((start + cursor) as u64),
                bytes: hex(length as u64),
            },
            length: hex(length as u64),
            revision,
            certificate_type,
            certificate_type_name: pe_certificate_type_name(certificate_type),
            raw_base64: base64(raw),
            malformed: false,
            unknown_reason: None,
        });
        let aligned_length = (entry_length + 7) & !7;
        let Some(next) = cursor.checked_add(aligned_length) else {
            malformed = true;
            unknown_reason = Some("certificate-entry-alignment-overflow");
            break;
        };
        if next > table_bytes.len() {
            malformed = true;
            unknown_reason = Some("truncated-certificate-entry-alignment");
            break;
        }
        cursor = next;
    }
    if entries.len() == 4096 {
        malformed = true;
        unknown_reason = Some("certificate-entry-count-exceeded-bound");
    }

    Ok(Some(PeCertificateTable {
        file_offset: hex(file_offset as u64),
        declared_size: hex(declared_size as u64),
        observed_size: hex((observed_end - start) as u64),
        location: Some(Range {
            offset: hex(file_offset as u64),
            bytes: hex((observed_end - start) as u64),
        }),
        entries,
        malformed,
        unknown_reason,
    }))
}

fn pe_certificate_type_name(certificate_type: u16) -> &'static str {
    match certificate_type {
        1 => "WIN_CERT_TYPE_X509",
        2 => "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
        3 => "WIN_CERT_TYPE_X509_PHY_TYPE",
        9 => "WIN_CERT_TYPE_PKCS1_SIGN",
        _ => "WIN_CERT_TYPE_UNKNOWN",
    }
}

fn malformed_pe_certificate_table(
    file_offset: u32,
    declared_size: u32,
    reason: &'static str,
) -> PeCertificateTable {
    PeCertificateTable {
        file_offset: hex(file_offset as u64),
        declared_size: hex(declared_size as u64),
        observed_size: "0x0".to_owned(),
        location: None,
        entries: Vec::new(),
        malformed: true,
        unknown_reason: Some(reason),
    }
}

fn pe_data_directory(
    bytes: &[u8],
    optional_offset: usize,
    optional_size: usize,
    index: usize,
) -> Result<Option<(u32, u32)>, Error> {
    if optional_size < 2 {
        return Ok(None);
    }
    let magic = u16::from_le_bytes(
        bytes[optional_offset..optional_offset + 2]
            .try_into()
            .unwrap(),
    );
    let directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return Ok(None),
    };
    let count_offset: usize = directory_offset - 4;
    if optional_size < count_offset + 4 {
        return Ok(None);
    }
    let count = u32::from_le_bytes(
        bytes[optional_offset + count_offset..optional_offset + count_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if index >= count || optional_size < directory_offset + (index + 1) * 8 {
        return Ok(None);
    }
    let entry = optional_offset + directory_offset + index * 8;
    Ok(Some((
        u32::from_le_bytes(bytes[entry..entry + 4].try_into().unwrap()),
        u32::from_le_bytes(bytes[entry + 4..entry + 8].try_into().unwrap()),
    )))
}

fn pe_header_offset(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.get(0..2) != Some(b"MZ") {
        return Err(Error::Format(
            "Selected object does not contain a DOS header.",
        ));
    }
    let offset = u32::from_le_bytes(
        bytes
            .get(0x3c..0x40)
            .ok_or(Error::Format("PE DOS header is truncated"))?
            .try_into()
            .unwrap(),
    ) as usize;
    if bytes.get(offset..offset + 4) != Some(b"PE\0\0") {
        return Err(Error::Format("PE signature is truncated or invalid"));
    }
    Ok(offset)
}

fn pe_headers(bytes: &[u8], pe_offset: usize) -> Result<(usize, usize, usize), Error> {
    let coff = pe_offset
        .checked_add(4)
        .ok_or(Error::Format("PE header range overflowed"))?;
    let section_count = u16::from_le_bytes(
        bytes
            .get(coff + 2..coff + 4)
            .ok_or(Error::Format("PE COFF header is truncated"))?
            .try_into()
            .unwrap(),
    ) as usize;
    if section_count > 96 {
        return Err(Error::Format("PE section table exceeds the admitted bound"));
    }
    let optional_size = u16::from_le_bytes(
        bytes
            .get(coff + 16..coff + 18)
            .ok_or(Error::Format("PE COFF header is truncated"))?
            .try_into()
            .unwrap(),
    ) as usize;
    let optional_offset = coff
        .checked_add(20)
        .ok_or(Error::Format("PE optional header range overflowed"))?;
    let optional_end = optional_offset
        .checked_add(optional_size)
        .ok_or(Error::Format("PE optional header range overflowed"))?;
    if bytes.len() < optional_end {
        return Err(Error::Format("PE optional header is truncated"));
    }
    Ok((optional_offset, optional_size, section_count))
}

/// Project the PE header fields used to validate image extent and entry-point
/// ownership. Values remain raw even when the declared image is malformed.
pub fn parse_pe_header_metadata(bytes: &[u8]) -> Result<PeHeaderMetadata, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }

    let pe_offset = pe_header_offset(bytes)?;
    let (optional_offset, optional_size, section_count) = pe_headers(bytes, pe_offset)?;
    if optional_size < 72 {
        return Err(Error::Format("PE optional header lacks required metadata"));
    }
    let coff_offset = pe_offset + 4;
    let machine = u16::from_le_bytes(bytes[coff_offset..coff_offset + 2].try_into().unwrap());
    let coff_characteristics = u16::from_le_bytes(
        bytes[coff_offset + 14..coff_offset + 16]
            .try_into()
            .unwrap(),
    );
    let magic = u16::from_le_bytes(
        bytes[optional_offset..optional_offset + 2]
            .try_into()
            .unwrap(),
    );
    let (image_base, image_base_overflow) = match magic {
        0x10b => (
            u64::from(u32::from_le_bytes(
                bytes[optional_offset + 28..optional_offset + 32]
                    .try_into()
                    .unwrap(),
            )),
            false,
        ),
        0x20b => (
            u64::from_le_bytes(
                bytes[optional_offset + 24..optional_offset + 32]
                    .try_into()
                    .unwrap(),
            ),
            false,
        ),
        _ => (0, true),
    };
    let entry_point = u32::from_le_bytes(
        bytes[optional_offset + 16..optional_offset + 20]
            .try_into()
            .unwrap(),
    );
    let size_of_image = u32::from_le_bytes(
        bytes[optional_offset + 56..optional_offset + 60]
            .try_into()
            .unwrap(),
    );
    let size_of_headers = u32::from_le_bytes(
        bytes[optional_offset + 60..optional_offset + 64]
            .try_into()
            .unwrap(),
    );
    let subsystem = u16::from_le_bytes(
        bytes[optional_offset + 68..optional_offset + 70]
            .try_into()
            .unwrap(),
    );
    let dll_characteristics = u16::from_le_bytes(
        bytes[optional_offset + 70..optional_offset + 72]
            .try_into()
            .unwrap(),
    );

    let invalid_extent = size_of_image == 0 || size_of_headers > size_of_image;
    let invalid_entry_point = entry_point != 0 && entry_point >= size_of_image;
    let malformed = image_base_overflow || invalid_extent || invalid_entry_point;
    let unknown_reason = if image_base_overflow {
        Some("unsupported-pe-optional-header-magic")
    } else if invalid_extent {
        Some("invalid-pe-image-extent")
    } else if invalid_entry_point {
        Some("pe-entry-point-outside-image")
    } else {
        None
    };

    Ok(PeHeaderMetadata {
        machine: hex(machine as u64),
        section_count,
        coff_characteristics: hex(coff_characteristics as u64),
        optional_magic: hex(magic as u64),
        image_base: hex(image_base),
        entry_point_rva: hex(entry_point as u64),
        size_of_image: hex(size_of_image as u64),
        size_of_headers: hex(size_of_headers as u64),
        subsystem,
        dll_characteristics: hex(dll_characteristics as u64),
        malformed,
        unknown_reason,
    })
}

/// Enumerate bounded PE resource leaves while retaining resource-tree ranges.
/// Payload bytes are intentionally not interpreted by this structural reader.
pub fn parse_pe_resources(bytes: &[u8]) -> Result<Vec<PeResourceEntry>, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }
    let pe_offset = pe_header_offset(bytes)?;
    let (optional_offset, optional_size, section_count) = pe_headers(bytes, pe_offset)?;
    let (_, _, size_of_headers) = pe_debug_data(bytes, optional_offset, optional_size)?;
    let sections = pe_sections(bytes, optional_offset, optional_size, section_count)?;
    let Some((resource_rva, resource_size)) =
        pe_data_directory(bytes, optional_offset, optional_size, 2)?
    else {
        return Ok(Vec::new());
    };
    if resource_rva == 0 || resource_size == 0 {
        return Ok(Vec::new());
    }
    let Some(root_offset) =
        pe_rva_to_file_offset(resource_rva, 16, size_of_headers, &sections, bytes.len())
    else {
        return Ok(vec![malformed_pe_resource_entry(
            "resource-directory-range-outside-snapshot",
        )]);
    };
    let resource_end = resource_rva
        .checked_add(resource_size)
        .ok_or(Error::Format("PE resource directory range overflowed"))?;
    let mut entries = Vec::new();
    walk_pe_resource_directory(
        bytes,
        &sections,
        size_of_headers,
        resource_rva,
        resource_end,
        root_offset,
        Vec::new(),
        0,
        &mut entries,
    )?;
    Ok(entries)
}

fn walk_pe_resource_directory(
    bytes: &[u8],
    sections: &[PeSection],
    size_of_headers: u32,
    resource_rva: u32,
    resource_end: u32,
    directory_offset: usize,
    path: Vec<String>,
    depth: usize,
    entries: &mut Vec<PeResourceEntry>,
) -> Result<(), Error> {
    if depth > 16 || entries.len() >= 4096 {
        entries.push(malformed_pe_resource_entry("resource-tree-bound-exceeded"));
        return Ok(());
    }
    let Some(directory) = bytes.get(directory_offset..directory_offset + 16) else {
        entries.push(malformed_pe_resource_entry("truncated-resource-directory"));
        return Ok(());
    };
    let named = u16::from_le_bytes(directory[12..14].try_into().unwrap()) as usize;
    let ids = u16::from_le_bytes(directory[14..16].try_into().unwrap()) as usize;
    let count = named.saturating_add(ids);
    let Some(entry_end) = directory_offset.checked_add(16 + count * 8) else {
        entries.push(malformed_pe_resource_entry("resource-entry-range-overflow"));
        return Ok(());
    };
    if entry_end > bytes.len() {
        entries.push(malformed_pe_resource_entry(
            "truncated-resource-entry-table",
        ));
        return Ok(());
    }
    for index in 0..count {
        let at = directory_offset + 16 + index * 8;
        let name = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let target = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
        let mut child_path = path.clone();
        child_path.push(pe_resource_name(bytes, resource_rva, resource_end, name)?);
        if target & 0x8000_0000 != 0 {
            let child_rva = resource_rva.checked_add(target & 0x7fff_ffff);
            let Some(child_rva) = child_rva.filter(|rva| *rva < resource_end) else {
                entries.push(malformed_pe_resource_entry(
                    "resource-child-directory-outside",
                ));
                continue;
            };
            let Some(child_offset) =
                pe_rva_to_file_offset(child_rva, 16, size_of_headers, sections, bytes.len())
            else {
                entries.push(malformed_pe_resource_entry(
                    "resource-child-directory-unmapped",
                ));
                continue;
            };
            walk_pe_resource_directory(
                bytes,
                sections,
                size_of_headers,
                resource_rva,
                resource_end,
                child_offset,
                child_path,
                depth + 1,
                entries,
            )?;
            continue;
        }
        let data_rva = resource_rva.checked_add(target);
        let Some(data_rva) = data_rva.filter(|rva| *rva < resource_end) else {
            entries.push(malformed_pe_resource_entry("resource-data-entry-outside"));
            continue;
        };
        let Some(data_offset) =
            pe_rva_to_file_offset(data_rva, 16, size_of_headers, sections, bytes.len())
        else {
            entries.push(malformed_pe_resource_entry("resource-data-entry-unmapped"));
            continue;
        };
        let data = &bytes[data_offset..data_offset + 16];
        let payload_rva = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let payload_size = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let code_page = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let payload_location = pe_rva_to_file_offset(
            payload_rva,
            payload_size as usize,
            size_of_headers,
            sections,
            bytes.len(),
        )
        .and_then(|offset| checked_range_from_snapshot(bytes.len(), offset, payload_size as usize));
        entries.push(PeResourceEntry {
            path: child_path,
            directory_location: Range {
                offset: hex(directory_offset as u64),
                bytes: hex((entry_end - directory_offset) as u64),
            },
            data_location: Some(Range {
                offset: hex(data_offset as u64),
                bytes: hex(16),
            }),
            data_rva: hex(payload_rva as u64),
            data_size: hex(payload_size as u64),
            code_page,
            malformed: payload_location.is_none(),
            unknown_reason: payload_location
                .is_none()
                .then_some("resource-payload-outside-snapshot"),
        });
    }
    Ok(())
}

fn pe_resource_name(
    bytes: &[u8],
    resource_rva: u32,
    resource_end: u32,
    raw_name: u32,
) -> Result<String, Error> {
    if raw_name & 0x8000_0000 == 0 {
        return Ok(format!("id:{}", raw_name));
    }
    let name_rva = resource_rva
        .checked_add(raw_name & 0x7fff_ffff)
        .ok_or(Error::Format("PE resource name range overflowed"))?;
    if name_rva >= resource_end {
        return Ok(format!("name-offset:{}", hex(raw_name as u64)));
    }
    let name_offset = name_rva as usize;
    let Some(length_bytes) = bytes.get(name_offset..name_offset + 2) else {
        return Ok(format!("name-offset:{}", hex(raw_name as u64)));
    };
    let length = u16::from_le_bytes(length_bytes.try_into().unwrap()) as usize;
    let byte_length = length.saturating_mul(2);
    let Some(raw) = bytes.get(name_offset + 2..name_offset + 2 + byte_length) else {
        return Ok(format!("name-offset:{}", hex(raw_name as u64)));
    };
    let utf16: Vec<u16> = raw
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&utf16))
}

fn malformed_pe_resource_entry(reason: &'static str) -> PeResourceEntry {
    PeResourceEntry {
        path: Vec::new(),
        directory_location: Range {
            offset: "0x0".into(),
            bytes: "0x0".into(),
        },
        data_location: None,
        data_rva: "0x0".into(),
        data_size: "0x0".into(),
        code_page: 0,
        malformed: true,
        unknown_reason: Some(reason),
    }
}

fn pe_debug_data(
    bytes: &[u8],
    optional_offset: usize,
    optional_size: usize,
) -> Result<(u32, u32, u32), Error> {
    if optional_size < 64 {
        return Ok((0, 0, 0));
    }
    let magic = u16::from_le_bytes(
        bytes[optional_offset..optional_offset + 2]
            .try_into()
            .unwrap(),
    );
    let directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return Ok((0, 0, 0)),
    };
    let count_offset = directory_offset - 4;
    if optional_size < count_offset + 4 {
        return Ok((0, 0, 0));
    }
    let directory_count = u32::from_le_bytes(
        bytes[optional_offset + count_offset..optional_offset + count_offset + 4]
            .try_into()
            .unwrap(),
    );
    let debug_offset = directory_offset + 6 * 8;
    if directory_count <= 6 || optional_size < debug_offset + 8 {
        return Ok((0, 0, 0));
    }
    let debug_rva = u32::from_le_bytes(
        bytes[optional_offset + debug_offset..optional_offset + debug_offset + 4]
            .try_into()
            .unwrap(),
    );
    let debug_size = u32::from_le_bytes(
        bytes[optional_offset + debug_offset + 4..optional_offset + debug_offset + 8]
            .try_into()
            .unwrap(),
    );
    let size_of_headers = u32::from_le_bytes(
        bytes[optional_offset + 60..optional_offset + 64]
            .try_into()
            .unwrap(),
    );
    Ok((debug_rva, debug_size, size_of_headers))
}

#[derive(Clone, Copy)]
struct PeSection {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
}

fn pe_sections(
    bytes: &[u8],
    optional_offset: usize,
    optional_size: usize,
    count: usize,
) -> Result<Vec<PeSection>, Error> {
    let table = optional_offset
        .checked_add(optional_size)
        .ok_or(Error::Format("PE section table range overflowed"))?;
    let table_size = count
        .checked_mul(40)
        .ok_or(Error::Format("PE section table range overflowed"))?;
    if bytes.len() < table + table_size {
        return Err(Error::Format("PE section table is truncated"));
    }
    (0..count)
        .map(|index| {
            let at = table + index * 40;
            Ok(PeSection {
                virtual_size: u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()),
                virtual_address: u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap()),
                raw_size: u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap()),
                raw_pointer: u32::from_le_bytes(bytes[at + 20..at + 24].try_into().unwrap()),
            })
        })
        .collect()
}

fn pe_rva_to_file_offset(
    rva: u32,
    size: usize,
    size_of_headers: u32,
    sections: &[PeSection],
    snapshot_len: usize,
) -> Option<usize> {
    let rva = rva as usize;
    if rva < size_of_headers as usize {
        let end = rva.checked_add(size)?;
        return (end <= size_of_headers as usize && end <= snapshot_len).then_some(rva);
    }
    sections.iter().find_map(|section| {
        let start = section.virtual_address as usize;
        let span = (section.virtual_size as usize).max(section.raw_size as usize);
        let relative = rva.checked_sub(start)?;
        let file_offset = (section.raw_pointer as usize).checked_add(relative)?;
        (relative.checked_add(size)? <= section.raw_size as usize
            && file_offset.checked_add(size)? <= snapshot_len
            && relative < span)
            .then_some(file_offset)
    })
}

fn parse_pe_debug_entry(
    index: usize,
    bytes: &[u8],
    base_offset: usize,
    size_of_headers: u32,
    sections: &[PeSection],
    snapshot_len: usize,
) -> Result<PeDebugDirectoryEntry, Error> {
    let at = index * PE_DEBUG_DIRECTORY_ENTRY_BYTES;
    let raw_type = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
    let size_of_data = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap());
    let data_rva = u32::from_le_bytes(bytes[at + 20..at + 24].try_into().unwrap());
    let file_pointer = u32::from_le_bytes(bytes[at + 24..at + 28].try_into().unwrap());
    let data_offset = if file_pointer != 0 {
        Some(file_pointer as usize)
    } else {
        pe_rva_to_file_offset(
            data_rva,
            size_of_data as usize,
            size_of_headers,
            sections,
            snapshot_len,
        )
    };
    let data_location = data_offset.and_then(|offset| {
        checked_range_from_snapshot(snapshot_len, offset, size_of_data as usize)
    });
    let invalid_data = size_of_data != 0 && data_location.is_none();
    Ok(PeDebugDirectoryEntry {
        index,
        debug_type: pe_debug_type_name(raw_type),
        raw_type: hex(raw_type as u64),
        timestamp: hex(u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as u64),
        major_version: u16::from_le_bytes(bytes[at + 8..at + 10].try_into().unwrap()),
        minor_version: u16::from_le_bytes(bytes[at + 10..at + 12].try_into().unwrap()),
        size_of_data: hex(size_of_data as u64),
        data_rva: hex(data_rva as u64),
        file_pointer: hex(file_pointer as u64),
        directory_location: Some(Range {
            offset: hex((base_offset + at) as u64),
            bytes: hex(PE_DEBUG_DIRECTORY_ENTRY_BYTES as u64),
        }),
        data_location,
        malformed: invalid_data,
        unknown_reason: invalid_data.then_some("debug-data-range-outside-snapshot"),
    })
}

fn checked_range_from_snapshot(snapshot_len: usize, offset: usize, size: usize) -> Option<Range> {
    let end = offset.checked_add(size)?;
    (end <= snapshot_len).then_some(Range {
        offset: hex(offset as u64),
        bytes: hex(size as u64),
    })
}

fn malformed_pe_debug_entry(
    index: usize,
    directory_location: Option<Range>,
    size_of_data: u32,
    data_rva: u32,
    file_pointer: u32,
    reason: &'static str,
) -> PeDebugDirectoryEntry {
    PeDebugDirectoryEntry {
        index,
        debug_type: "IMAGE_DEBUG_TYPE_UNKNOWN",
        raw_type: "unknown".to_owned(),
        timestamp: "unknown".to_owned(),
        major_version: 0,
        minor_version: 0,
        size_of_data: hex(size_of_data as u64),
        data_rva: hex(data_rva as u64),
        file_pointer: hex(file_pointer as u64),
        directory_location,
        data_location: None,
        malformed: true,
        unknown_reason: Some(reason),
    }
}

fn pe_debug_type_name(raw_type: u32) -> &'static str {
    match raw_type {
        0 => "IMAGE_DEBUG_TYPE_UNKNOWN",
        1 => "IMAGE_DEBUG_TYPE_COFF",
        2 => "IMAGE_DEBUG_TYPE_CODEVIEW",
        3 => "IMAGE_DEBUG_TYPE_FPO",
        4 => "IMAGE_DEBUG_TYPE_MISC",
        5 => "IMAGE_DEBUG_TYPE_EXCEPTION",
        6 => "IMAGE_DEBUG_TYPE_FIXUP",
        7 => "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
        8 => "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
        9 => "IMAGE_DEBUG_TYPE_BORLAND",
        11 => "IMAGE_DEBUG_TYPE_CLSID",
        12 => "IMAGE_DEBUG_TYPE_VC_FEATURE",
        13 => "IMAGE_DEBUG_TYPE_POGO",
        14 => "IMAGE_DEBUG_TYPE_ILTCG",
        15 => "IMAGE_DEBUG_TYPE_MPX",
        16 => "IMAGE_DEBUG_TYPE_REPRO",
        20 => "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
        21 => "IMAGE_DEBUG_TYPE_EXECLLCHARACTERISTICS",
        _ => "IMAGE_DEBUG_TYPE_UNKNOWN",
    }
}

fn extended_symbol_indices(
    bytes: &[u8],
    sections: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    symbol_table: usize,
    count: usize,
    little: bool,
) -> Result<Option<Vec<u32>>, Error> {
    let Some(index_section) = sections
        .iter()
        .find(|section| section.0 == 18 && section.5 == symbol_table)
    else {
        return Ok(None);
    };
    if index_section.4 / 4 < count as u64 || index_section.4 % 4 != 0 {
        return Err(Error::Format(
            "ELF symbol extended-index table is truncated or misaligned",
        ));
    }
    checked_range(bytes, index_section.3, index_section.4)?;
    let mut indices = Vec::with_capacity(count);
    for entry in 0..count {
        indices.push(u32e(
            bytes,
            (index_section.3 + entry as u64 * 4) as usize,
            little,
        )?);
    }
    Ok(Some(indices))
}
fn u16e(b: &[u8], o: usize, little: bool) -> Result<u16, Error> {
    b.get(o..o + 2)
        .map(|x| {
            if little {
                u16::from_le_bytes([x[0], x[1]])
            } else {
                u16::from_be_bytes([x[0], x[1]])
            }
        })
        .ok_or(Error::Format("ELF header is truncated"))
}
fn u32e(b: &[u8], o: usize, little: bool) -> Result<u32, Error> {
    b.get(o..o + 4)
        .map(|x| {
            if little {
                u32::from_le_bytes([x[0], x[1], x[2], x[3]])
            } else {
                u32::from_be_bytes([x[0], x[1], x[2], x[3]])
            }
        })
        .ok_or(Error::Format("ELF field is truncated"))
}
fn u64e(b: &[u8], o: usize, little: bool) -> Result<u64, Error> {
    b.get(o..o + 8)
        .map(|x| {
            if little {
                u64::from_le_bytes(x.try_into().unwrap())
            } else {
                u64::from_be_bytes(x.try_into().unwrap())
            }
        })
        .ok_or(Error::Format("ELF field is truncated"))
}
fn string_name(bytes: &[u8], table: Option<(u64, u64)>, offset: u32) -> Result<Name, Error> {
    let Some((start, size)) = table else {
        return Ok(Name {
            display: String::new(),
            bytes_base64: None,
            location: None,
            unknown_reason: Some("ELF declares no section-name table (SHN_UNDEF index 0).".into()),
        });
    };
    if u64::from(offset) >= size {
        return Err(Error::Format(
            "ELF name offset lies outside its declared string table",
        ));
    }
    let pos = (start + u64::from(offset)) as usize;
    let end = (start + size) as usize;
    let tail = bytes
        .get(pos..end)
        .ok_or(Error::Format("ELF string table is outside the snapshot"))?;
    let nul = tail.iter().position(|x| *x == 0).ok_or(Error::Format(
        "ELF name lacks a terminator within its reported string table",
    ))?;
    let raw = &tail[..nul];
    Ok(Name {
        display: String::from_utf8_lossy(raw).into_owned(),
        bytes_base64: Some(base64(raw)),
        location: Some(Range {
            offset: hex(pos as u64),
            bytes: hex((nul + 1) as u64),
        }),
        unknown_reason: None,
    })
}
fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | (chunk.get(2).copied().unwrap_or(0) as u32);
        out.push(A[(n >> 18) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn symbol_value_meaning(et: u16, section_index: u16, info: u8, value: u64) -> &'static str {
    if section_index == 0 {
        "undefined"
    } else if section_index == 0xfff2 {
        "alignment"
    } else if section_index == 0xfff1 {
        "absolute-value"
    } else if section_index >= 0xff00 {
        "unknown-section-index"
    } else if info & 15 == 6 {
        "tls-offset"
    } else if value == 0 {
        "no-address"
    } else if et == 1 {
        "section-offset"
    } else {
        "linked-virtual-address"
    }
}

/// Parse the complete bounded ELF64 layout projection used by the native adapter.
pub fn read(bytes: &[u8]) -> Result<Layout, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }
    if bytes.get(0..4) != Some(b"\x7fELF") {
        return Err(Error::Format(
            "Selected object does not contain an ELF header.",
        ));
    }
    if bytes.len() < 16 || !matches!(bytes[5], 1 | 2) {
        return Err(Error::Unsupported(
            "Initial layout profile requires ELF32 or ELF64 objects.",
        ));
    }
    let little = bytes[5] == 1;
    if bytes[4] == 1 {
        return read_elf32(bytes, little);
    }
    if bytes.len() < 64 {
        return Err(Error::Format("ELF64 header is truncated"));
    }
    if u16e(bytes, 18, little)? != 62 {
        return Err(Error::Unsupported(
            "Initial layout profile requires x86-64 ELF objects.",
        ));
    }
    let et = u16e(bytes, 16, little)?;
    let image_type=match et {1=>"ET_REL",2=>"ET_EXEC",3=>"ET_DYN",_=>return Err(Error::Unsupported("Selected ELF type is outside the EXEC/DYN/REL layout profile; recorded core analysis is separate."))}.to_owned();
    let entry = u64e(bytes, 24, little)?;
    let shoff = u64e(bytes, 40, little)?;
    let phoff = u64e(bytes, 32, little)?;
    let shentsize = u16e(bytes, 58, little)? as u64;
    let shnum = u16e(bytes, 60, little)? as u64;
    let shstr = u16e(bytes, 62, little)? as u64;
    let phentsize = u16e(bytes, 54, little)? as u64;
    let phnum = u16e(bytes, 56, little)? as u64;
    let mut extended_numbering = None;
    let mut shnum = shnum;
    let mut shstr = shstr;
    let mut phnum = phnum;
    if (0xff00..0xffff).contains(&shstr) {
        return Err(Error::Format(
            "ELF section-name index is reserved and cannot directly reference a section",
        ));
    }
    if (shnum == 0 && shoff != 0) || shstr == 0xffff || phnum == 0xffff {
        if shentsize < 64 {
            return Err(Error::Format(
                "invalid ELF section-zero width for extended numbering",
            ));
        }
        if shstr == 0xffff && shoff == 0 {
            return Err(Error::Format(
                "ELF extended section-name index requires a declared section-zero header",
            ));
        }
        let zero_location = checked_range(bytes, shoff, 64)?;
        let zero = shoff as usize;
        let zero_size = u64e(bytes, zero + 32, little)?;
        let zero_link = u32e(bytes, zero + 40, little)? as u64;
        let zero_info = u32e(bytes, zero + 44, little)? as u64;
        if shstr == 0xffff && shnum == 0 && zero_size == 0 {
            return Err(Error::Format(
                "ELF extended section-name index requires a declared section-zero header",
            ));
        }
        let resolved_shnum = if shnum == 0 { Some(zero_size) } else { None };
        let resolved_phnum = if phnum == 0xffff {
            Some(zero_info)
        } else {
            None
        };
        let resolved_shstr = if shstr == 0xffff {
            Some(zero_link)
        } else {
            None
        };
        if shstr == 0xffff && zero_link != 0 && zero_link < 0xff00 {
            return Err(Error::Format(
                "ELF SHN_XINDEX resolves to an ordinary section-name index; the escape requires an index at least SHN_LORESERVE",
            ));
        }
        if let Some(value) = resolved_shnum {
            shnum = value;
        }
        if let Some(value) = resolved_phnum {
            phnum = value;
        }
        if let Some(value) = resolved_shstr {
            shstr = value;
        }
        extended_numbering = Some(ExtendedNumbering {
            section_count: resolved_shnum,
            program_count: resolved_phnum,
            section_name_index: resolved_shstr,
            section_zero_location: zero_location,
        });
    }
    if shentsize < 64 && shnum > 0 {
        return Err(Error::Format("invalid ELF section width"));
    }
    let mut raw_sections = Vec::new();
    for i in 0..shnum {
        let o = shoff
            .checked_add(
                i.checked_mul(shentsize)
                    .ok_or(Error::Format("section table overflow"))?,
            )
            .ok_or(Error::Format("section table overflow"))?;
        let p = o as usize;
        let kind = u32e(bytes, p + 4, little)?;
        let flags = u64e(bytes, p + 8, little)?;
        let addr = u64e(bytes, p + 16, little)?;
        let off = u64e(bytes, p + 24, little)?;
        let size = u64e(bytes, p + 32, little)?;
        let link = u32e(bytes, p + 40, little)? as usize;
        let info = u32e(bytes, p + 44, little)? as usize;
        let align = u64e(bytes, p + 48, little)?;
        let entsize = u64e(bytes, p + 56, little)?;
        let name = u32e(bytes, p, little)?;
        if kind != 8 && kind != 0 {
            checked_range(bytes, off, size)?;
        }
        raw_sections.push((
            kind, flags, addr, off, size, link, info, align, entsize, name,
        ));
    }
    let names_table = if shstr == 0 {
        None
    } else {
        let x = raw_sections.get(shstr as usize).ok_or(Error::Format(
            "ELF section-name table index lies outside section count",
        ))?;
        if x.0 != 3 {
            return Err(Error::Format("ELF section-name table is not SHT_STRTAB"));
        }
        checked_range(bytes, x.3, x.4)?;
        Some((x.3, x.4))
    };
    let mut sections = Vec::new();
    for (i, x) in raw_sections.iter().enumerate() {
        sections.push(Section {
            index: i,
            name: string_name(bytes, names_table, x.9)?,
            name_offset: hex(x.9 as u64),
            kind: section_kind(x.0),
            header_location: checked_range(bytes, shoff + (i as u64) * shentsize, shentsize)?,
            address: hex(x.2),
            offset: hex(x.3),
            size: hex(x.4),
            alignment: hex(x.7),
            flags: hex(x.1),
            link: x.5,
            info: x.6,
            entry_size: hex(x.8 as u64),
            file_backing: if x.0 == 0 || x.0 == 8 { "none" } else { "file" },
            compression: compressed_section(bytes, x.1, x.3, x.4, little, 64)?,
        });
    }
    let mut segments = Vec::new();
    let mut execstack = false;
    let mut stack_policy = None;
    let mut relro_policy = None;
    let mut tls_segments = Vec::new();
    let mut eh_frame_segments = Vec::new();
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        let p = o as usize;
        let kind = u32e(bytes, p, little)?;
        let flags = u32e(bytes, p + 4, little)?;
        let off = u64e(bytes, p + 8, little)?;
        let va = u64e(bytes, p + 16, little)?;
        let pa = u64e(bytes, p + 24, little)?;
        let fs = u64e(bytes, p + 32, little)?;
        let ms = u64e(bytes, p + 40, little)?;
        let al = u64e(bytes, p + 48, little)?;
        if kind == 1 && ms < fs {
            return Err(Error::Format(
                "ELF load segment memory size is smaller than its file size.",
            ));
        }
        if kind != 0 && fs > 0 {
            checked_range(bytes, off, fs)?;
        }
        if kind == 0x6474e551 {
            execstack = flags & 1 != 0;
            stack_policy = Some(stack_policy_metadata(
                i as usize,
                flags,
                checked_range(bytes, o, phentsize)?,
                stack_policy.is_some(),
            ));
        }
        if kind == 0x6474e552 {
            relro_policy = Some(relro_segment_metadata(
                i as usize,
                off,
                fs,
                va,
                ms,
                flags,
                checked_range(bytes, o, phentsize)?,
                relro_policy.is_some(),
                checked_range(bytes, off, fs).ok(),
            ));
        }
        if kind == 7 {
            tls_segments.push(tls_segment_metadata(
                i as usize,
                off,
                fs,
                va,
                ms,
                al,
                flags,
                checked_range(bytes, o, phentsize)?,
                checked_range(bytes, off, fs).ok(),
            ));
        }
        if kind == 0x6474e550 {
            eh_frame_segments.push(eh_frame_segment_metadata(
                i as usize,
                off,
                fs,
                va,
                ms,
                al,
                flags,
                checked_range(bytes, off, fs).ok(),
            ));
        }
        segments.push(Segment {
            index: i as usize,
            kind: segment_kind(kind),
            header_location: checked_range(bytes, o, phentsize)?,
            offset: hex(off),
            file_size: hex(fs),
            memory_size: hex(ms),
            virtual_address: hex(va),
            physical_address: hex(pa),
            alignment: hex(al),
            flags: hex(flags as u64),
            file_backing: if kind != 0 && fs > 0 { "file" } else { "none" },
            permissions: if kind == 0 {
                None
            } else {
                Some(Permissions {
                    read: flags & 4 != 0,
                    write: flags & 2 != 0,
                    execute: flags & 1 != 0,
                })
            },
        });
    }
    let mut symbols = Vec::new();
    let mut relocations = Vec::new();
    for (table, x) in raw_sections.iter().enumerate() {
        if x.0 == 2 || x.0 == 11 {
            validate_symbol_table_layout(
                x.8,
                x.4,
                24,
                "ELF symbol entry is smaller than the decoded Elf64_Sym structure.",
            )?;
            let strtab = Some(validate_symbol_string_table(&raw_sections, x.5)?);
            let count = (x.4 / x.8) as usize;
            let extended_indices =
                extended_symbol_indices(bytes, &raw_sections, table, count, little)?;
            for e in 0..count {
                let p = (x.3 + e as u64 * x.8) as usize;
                let name = u32e(bytes, p, little)?;
                let info = bytes
                    .get(p + 4)
                    .copied()
                    .ok_or(Error::Format("symbol entry truncated"))?;
                let other = bytes
                    .get(p + 5)
                    .copied()
                    .ok_or(Error::Format("symbol entry truncated"))?;
                let shndx = u16e(bytes, p + 6, little)?;
                let reported_section_index = shndx.to_string();
                let resolved_section_index = if shndx == 0xffff {
                    extended_indices
                        .as_ref()
                        .and_then(|indices| indices.get(e))
                        .map(|index| index.to_string())
                        .unwrap_or_else(|| "SHN_XINDEX (unresolved)".into())
                } else {
                    reported_section_index.clone()
                };
                let value = u64e(bytes, p + 8, little)?;
                let size = u64e(bytes, p + 16, little)?;
                let meaning = symbol_value_meaning(et, shndx, info, value);
                symbols.push(Symbol {
                    table_index: table,
                    entry_index: e as usize,
                    name: string_name(bytes, strtab, name)?,
                    name_offset: hex(name as u64),
                    location: checked_range(bytes, x.3 + e as u64 * x.8, x.8)?,
                    value: hex(value),
                    value_meaning: meaning,
                    size: hex(size),
                    binding: symbol_binding(info >> 4),
                    kind: symbol_type(info & 15),
                    visibility: symbol_visibility(other & 3),
                    section_index: resolved_section_index,
                    reported_section_index,
                    version: None,
                    version_index: None,
                    version_location: None,
                    version_state: "unknown",
                    version_hidden: false,
                });
            }
        }
        if x.0 == 4 || x.0 == 9 {
            let width = if x.0 == 4 { 24 } else { 16 };
            if x.8 < width || x.4 % x.8 != 0 {
                return Err(Error::Format(
                    "ELF relocation section has an invalid entry width",
                ));
            }
            for e in 0..(x.4 / x.8) {
                let p = (x.3 + e * x.8) as usize;
                let off = u64e(bytes, p, little)?;
                let info = u64e(bytes, p + 8, little)?;
                let add = if width == 24 {
                    Some(u64e(bytes, p + 16, little)? as i64)
                } else {
                    None
                };
                validate_relocation_target_section(et, x.6, raw_sections.len())?;
                validate_relocation_symbol_index(&raw_sections, x.5, info >> 32)?;
                let target = if et == 1 {
                    let si = x.6;
                    if si == 0 {
                        RelocationTarget::UnknownSection {
                            reported_section_index: si,
                            offset: hex(off),
                            unknown_reason: "undefined-section-reference",
                        }
                    } else {
                        RelocationTarget::SectionOffset {
                            section_index: si,
                            offset: hex(off),
                        }
                    }
                } else {
                    RelocationTarget::LinkedVirtualAddress { address: hex(off) }
                };
                relocations.push(Relocation {
                    section_index: table,
                    entry_index: e as usize,
                    reported_offset: hex(off),
                    target,
                    location: checked_range(bytes, x.3 + e * x.8, x.8)?,
                    kind: (info & 0xffffffff) as usize,
                    symbol_table_index: x.5,
                    symbol_index: (info >> 32) as usize,
                    symbol_reference_meaning: if info >> 32 == 0 {
                        "zero-symbol-value"
                    } else {
                        "symbol-table-entry"
                    },
                    addend: add.map(|a| a.to_string()),
                    symbol: None,
                    symbol_version: None,
                    symbol_version_hidden: false,
                    symbol_resolution: "unresolved",
                });
            }
        }
    }
    let mut packed_relative_relocations = section_relr(bytes, &raw_sections, little, 64)?;
    packed_relative_relocations.extend(dynamic_relr(bytes, little, phoff, phnum, phentsize, 64)?);
    attach_section_versions(bytes, &raw_sections, little, &mut symbols)?;
    symbols.extend(dynamic_symbols(bytes, little, phoff, phnum, phentsize, 64)?);
    relocations.extend(dynamic_relocations(
        bytes, little, phoff, phnum, phentsize, 64,
    )?);
    attach_relocation_symbols(&mut relocations, &symbols);
    let stack_canary_indicator = has_stack_canary_symbols(&symbols);
    let (got, plt) = dynamic_linkage_maps(&relocations);
    let needed_libraries = dynamic_needed(bytes, little, phoff, phnum, phentsize, 64)?;
    let interpreters = interpreters(bytes, little, phoff, phnum, phentsize, 64)?;
    let mut notes = notes_from_segments(bytes, little, phoff, phnum, phentsize, 64)?;
    notes.extend(notes_from_sections(bytes, &raw_sections, little, 64)?);
    let debug_links = debug_links_from_sections(bytes, &sections, little)?;
    let section_groups = section_groups(bytes, &raw_sections, &symbols, little)?;
    let dynamic_flags = dynamic_flags(bytes, little, phoff, phnum, phentsize, 64)?;
    let relro = relro_mitigation(relro_policy.as_ref(), dynamic_flags.as_ref());
    let nx_indicator = nx_mitigation(stack_policy.as_ref());
    let dynamic_string_tags = dynamic_string_tags(bytes, little, phoff, phnum, phentsize, 64)?;
    let dynamic_gnu_hash = dynamic_gnu_hash(bytes, little, phoff, phnum, phentsize, 64)?;
    let symbol_version_tables = gnu_version_tables(bytes, &raw_sections, little)?;
    Ok(Layout {
        format: "elf",
        architecture: Architecture {
            machine: "EM_X86_64".into(),
            bits: 64,
            byte_order: if little { "little" } else { "big" }.into(),
        },
        image_type: image_type.clone(),
        entry_point: EntryPoint {
            reported_value: hex(entry),
            meaning: if et == 1 {
                "not-applicable"
            } else if entry == 0 {
                "absent"
            } else {
                "linked-virtual-address"
            },
            execution_status: "unknown",
        },
        runtime_load_base: None,
        sections,
        segments,
        symbols,
        relocations,
        packed_relative_relocations,
        relocation_inventory_completeness: "unknown",
        linkage: Linkage {
            needed_libraries,
            interpreters,
            got,
            plt,
            convenience_maps_completeness: "unknown",
            runtime_library_paths: None,
        },
        mitigations: Mitigations {
            evidence_kind: "inferred",
            position_independent: et == 3,
            nx_indicator,
            executable_stack_indicator: execstack,
            stack_canary_indicator,
            relro,
        },
        notes,
        debug_links,
        section_groups,
        extended_numbering,
        stack_policy,
        relro_policy,
        tls_segments,
        eh_frame_segments,
        dynamic_flags,
        dynamic_string_tags,
        dynamic_gnu_hash,
        symbol_version_tables,
    })
}

fn relro_segment_metadata(
    segment_index: usize,
    file_offset: u64,
    file_size: u64,
    virtual_address: u64,
    memory_size: u64,
    flags: u32,
    header_location: Range,
    duplicate: bool,
    source_location: Option<Range>,
) -> RelroPolicy {
    let malformed_extent = memory_size == 0 || file_size > memory_size;
    let malformed_source = source_location.is_none();
    let malformed = malformed_extent || malformed_source || duplicate;
    let unknown_reason = if duplicate {
        Some("duplicate-PT_GNU_RELRO-declaration")
    } else if malformed_source {
        Some("relro-range-outside-snapshot")
    } else if malformed_extent {
        Some("invalid-relro-range")
    } else {
        None
    };
    RelroPolicy {
        segment_index,
        file_offset: hex(file_offset),
        file_size: hex(file_size),
        virtual_address: hex(virtual_address),
        memory_size: hex(memory_size),
        flags: hex(flags as u64),
        header_location,
        source_location,
        policy: "present",
        duplicate,
        malformed,
        unknown_reason,
    }
}

fn relro_mitigation(policy: Option<&RelroPolicy>, flags: Option<&DynamicFlags>) -> Option<String> {
    let policy = policy?;
    if policy.malformed || flags.is_some_and(|value| value.malformed) {
        return None;
    }
    let full = flags.is_some_and(|value| {
        value.entries.iter().any(|entry| {
            matches!(entry.tag.as_str(), "0x18" | "0x1e" | "0x6ffffffb")
                && !entry.named_bits.is_empty()
        })
    });
    Some(if full { "Full" } else { "Partial" }.into())
}

fn nx_mitigation(policy: Option<&StackPolicy>) -> Option<bool> {
    let policy = policy?;
    if policy.malformed {
        return None;
    }
    Some(policy.policy == "non-executable")
}

fn tls_segment_metadata(
    segment_index: usize,
    file_offset: u64,
    file_size: u64,
    virtual_address: u64,
    memory_size: u64,
    alignment: u64,
    flags: u32,
    header_location: Range,
    source_location: Option<Range>,
) -> TlsSegment {
    let malformed = source_location.is_none()
        || memory_size < file_size
        || (alignment != 0 && !alignment.is_power_of_two());
    let unknown_reason = if source_location.is_none() {
        Some("tls-range-outside-snapshot")
    } else if memory_size < file_size {
        Some("invalid-tls-memory-extent")
    } else if alignment != 0 && !alignment.is_power_of_two() {
        Some("invalid-tls-alignment")
    } else {
        None
    };
    TlsSegment {
        segment_index,
        file_offset: hex(file_offset),
        file_size: hex(file_size),
        virtual_address: hex(virtual_address),
        memory_size: hex(memory_size),
        alignment: hex(alignment),
        flags: hex(flags as u64),
        header_location,
        source_location,
        malformed,
        unknown_reason,
    }
}

fn eh_frame_segment_metadata(
    segment_index: usize,
    file_offset: u64,
    file_size: u64,
    virtual_address: u64,
    memory_size: u64,
    alignment: u64,
    flags: u32,
    source_location: Option<Range>,
) -> EhFrameSegment {
    let malformed = source_location.is_none()
        || memory_size < file_size
        || (alignment != 0 && !alignment.is_power_of_two());
    let unknown_reason = if source_location.is_none() {
        Some("eh-frame-range-outside-snapshot")
    } else if memory_size < file_size {
        Some("invalid-eh-frame-memory-extent")
    } else if alignment != 0 && !alignment.is_power_of_two() {
        Some("invalid-eh-frame-alignment")
    } else {
        None
    };
    EhFrameSegment {
        segment_index,
        file_offset: hex(file_offset),
        file_size: hex(file_size),
        virtual_address: hex(virtual_address),
        memory_size: hex(memory_size),
        alignment: hex(alignment),
        flags: hex(flags as u64),
        source_location,
        malformed,
        unknown_reason,
    }
}

fn section_kind(v: u32) -> String {
    match v {
        0 => "SHT_NULL",
        1 => "SHT_PROGBITS",
        2 => "SHT_SYMTAB",
        3 => "SHT_STRTAB",
        4 => "SHT_RELA",
        5 => "SHT_HASH",
        6 => "SHT_DYNAMIC",
        7 => "SHT_NOTE",
        8 => "SHT_NOBITS",
        9 => "SHT_REL",
        10 => "SHT_SHLIB",
        11 => "SHT_DYNSYM",
        14 => "SHT_INIT_ARRAY",
        15 => "SHT_FINI_ARRAY",
        16 => "SHT_PREINIT_ARRAY",
        17 => "SHT_GROUP",
        18 => "SHT_SYMTAB_SHNDX",
        19 => "SHT_RELR",
        0x6ffffff5 => "SHT_GNU_ATTRIBUTES",
        0x6ffffff6 => "SHT_GNU_HASH",
        0x6ffffff7 => "SHT_GNU_LIBLIST",
        0x6ffffffd => "SHT_GNU_VERDEF",
        0x6ffffffe => "SHT_GNU_VERNEED",
        0x6fffffff => "SHT_GNU_VERSYM",
        _ => return format!("SHT_{v}"),
    }
    .into()
}

fn symbol_binding(value: u8) -> String {
    match value {
        0 => "STB_LOCAL",
        1 => "STB_GLOBAL",
        2 => "STB_WEAK",
        10 => "STB_GNU_UNIQUE",
        _ => return format!("STB_{value}"),
    }
    .into()
}

fn symbol_type(value: u8) -> String {
    match value {
        0 => "STT_NOTYPE",
        1 => "STT_OBJECT",
        2 => "STT_FUNC",
        3 => "STT_SECTION",
        4 => "STT_FILE",
        5 => "STT_COMMON",
        6 => "STT_TLS",
        10 => "STT_GNU_IFUNC",
        _ => return format!("STT_{value}"),
    }
    .into()
}

fn symbol_visibility(value: u8) -> String {
    match value {
        0 => "STV_DEFAULT",
        1 => "STV_INTERNAL",
        2 => "STV_HIDDEN",
        3 => "STV_PROTECTED",
        _ => return format!("STV_{value}"),
    }
    .into()
}

fn has_stack_canary_symbols(symbols: &[Symbol]) -> bool {
    symbols.iter().any(|symbol| {
        matches!(
            symbol.name.display.as_str(),
            "__stack_chk_fail" | "__stack_chk_guard" | "__stack_chk_fail_local"
        )
    })
}

fn compressed_section(
    bytes: &[u8],
    flags: u64,
    offset: u64,
    size: u64,
    little: bool,
    bits: u8,
) -> Result<Option<CompressionInfo>, Error> {
    if flags & 0x800 == 0 {
        return Ok(None);
    }
    let header_size = if bits == 64 { 24 } else { 12 };
    let location = checked_range(bytes, offset, size.min(header_size))?;
    if size < header_size {
        return Ok(Some(CompressionInfo {
            algorithm: "unknown".into(),
            raw_algorithm: "unknown".into(),
            declared_uncompressed_size: "unknown".into(),
            declared_alignment: "unknown".into(),
            header_location: location,
            malformed: true,
            unknown_reason: Some("truncated-compression-header"),
        }));
    }
    let kind = u32e(bytes, offset as usize, little)?;
    let (uncompressed_size, alignment) = if bits == 64 {
        (
            u64e(bytes, offset as usize + 8, little)?,
            u64e(bytes, offset as usize + 16, little)?,
        )
    } else {
        (
            u32e(bytes, offset as usize + 4, little)? as u64,
            u32e(bytes, offset as usize + 8, little)? as u64,
        )
    };
    let algorithm = match kind {
        1 => "zlib",
        _ => "unknown",
    };
    Ok(Some(CompressionInfo {
        algorithm: algorithm.into(),
        raw_algorithm: hex(kind as u64),
        declared_uncompressed_size: hex(uncompressed_size),
        declared_alignment: hex(alignment),
        header_location: location,
        malformed: kind != 1 || alignment == 0,
        unknown_reason: if kind != 1 {
            Some("unknown-compression-algorithm")
        } else if alignment == 0 {
            Some("zero-compression-alignment")
        } else {
            None
        },
    }))
}
fn segment_kind(v: u32) -> String {
    match v {
        0 => "PT_NULL",
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x60000000 => "PT_LOOS",
        0x6fffffff => "PT_HIOS",
        0x6474e550 => "PT_GNU_EH_FRAME",
        0x6474e551 => "PT_GNU_STACK",
        0x6474e552 => "PT_GNU_RELRO",
        0x6474e553 => "PT_GNU_PROPERTY",
        _ => return format!("PT_{v}"),
    }
    .into()
}

fn stack_policy_status(flags: u32) -> (bool, Option<&'static str>) {
    if flags & !0x7 != 0 {
        (true, Some("PT_GNU_STACK contains reserved permission bits"))
    } else {
        (false, None)
    }
}

fn stack_policy_metadata(
    segment_index: usize,
    flags: u32,
    header_location: Range,
    duplicate: bool,
) -> StackPolicy {
    let (invalid_flags, invalid_reason) = stack_policy_status(flags);
    let malformed = invalid_flags || duplicate;
    let unknown_reason = if duplicate {
        Some("duplicate-PT_GNU_STACK-declaration")
    } else {
        invalid_reason
    };
    StackPolicy {
        segment_index,
        flags: hex(flags as u64),
        policy: if flags & 1 != 0 {
            "executable"
        } else {
            "non-executable"
        },
        header_location,
        duplicate,
        malformed,
        unknown_reason,
    }
}

fn dynamic_needed(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Vec<Name>, Error> {
    let mut loads = Vec::new();
    let mut dynamic = None;
    for i in 0..phnum {
        let p = (phoff + i * phentsize) as usize;
        let kind = u32e(bytes, p, little)?;
        let (offset, vaddr, file_size) = if bits == 64 {
            (
                u64e(bytes, p + 8, little)?,
                u64e(bytes, p + 16, little)?,
                u64e(bytes, p + 32, little)?,
            )
        } else {
            (
                u32e(bytes, p + 4, little)? as u64,
                u32e(bytes, p + 8, little)? as u64,
                u32e(bytes, p + 16, little)? as u64,
            )
        };
        if kind == 1 {
            loads.push((vaddr, file_size, offset));
        }
        if kind == 2 {
            dynamic = Some((offset, file_size));
        }
    }
    let Some((offset, size)) = dynamic else {
        return Ok(Vec::new());
    };
    let entry_size: usize = if bits == 64 { 16 } else { 8 };
    let width = entry_size as u64;
    if size % width != 0 {
        return Err(Error::Format(
            "ELF dynamic segment has a misaligned reported entry range",
        ));
    }
    let end = offset
        .checked_add(size)
        .ok_or(Error::Format("ELF dynamic segment range overflowed"))?;
    checked_range(bytes, offset, size)?;
    let mut strtab = None;
    let mut strsz = None;
    let mut needed = Vec::new();
    let mut terminated = false;
    for at in (offset..end).step_by(entry_size) {
        let p = at as usize;
        let tag = if bits == 64 {
            u64e(bytes, p, little)?
        } else {
            u32e(bytes, p, little)? as u64
        };
        let value = if bits == 64 {
            u64e(bytes, p + 8, little)?
        } else {
            u32e(bytes, p + 4, little)? as u64
        };
        if tag == 0 {
            terminated = true;
            break;
        }
        match tag {
            5 => strtab = Some(value),
            10 => strsz = Some(value),
            1 => needed.push(value),
            _ => {}
        }
    }
    if !terminated {
        return Err(Error::Format(
            "ELF dynamic segment has no complete DT_NULL terminator within its reported file range",
        ));
    }
    if needed.is_empty() {
        return Ok(Vec::new());
    }
    let (Some(strtab), Some(strsz)) = (strtab, strsz) else {
        return Err(Error::Format(
            "ELF dependency requires DT_STRTAB and DT_STRSZ",
        ));
    };
    let mut mappings: Vec<u64> = loads
        .iter()
        .filter_map(|(virtual_start, load_size, file_offset)| {
            let virtual_end = virtual_start.checked_add(*load_size)?;
            let string_end = strtab.checked_add(strsz)?;
            (strtab >= *virtual_start && string_end <= virtual_end)
                .then_some(file_offset + (strtab - virtual_start))
        })
        .collect();
    mappings.sort_unstable();
    mappings.dedup();
    if mappings.len() != 1 {
        return Err(Error::Unsupported(
            "ELF dependency string table lacks a unique file-backed mapping",
        ));
    }
    let file_start = mappings[0];
    let table = checked_range(bytes, file_start, strsz)?;
    let table_start = u64::from_str_radix(table.offset.trim_start_matches("0x"), 16).unwrap_or(0);
    needed
        .into_iter()
        .map(|offset| string_name(bytes, Some((table_start, strsz)), offset as u32))
        .collect()
}

fn interpreters(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Vec<Name>, Error> {
    const MAX_INTERPRETER_BYTES: usize = 4096;
    let mut values = Vec::new();
    for index in 0..phnum.min(16_384) {
        let Some(position) = phoff
            .checked_add(index.saturating_mul(phentsize))
            .and_then(|value| usize::try_from(value).ok())
        else {
            continue;
        };
        if u32e(bytes, position, little)? != 3 {
            continue;
        }
        let (offset, size) = if bits == 64 {
            (
                u64e(bytes, position + 8, little)?,
                u64e(bytes, position + 32, little)?,
            )
        } else {
            (
                u32e(bytes, position + 4, little)? as u64,
                u32e(bytes, position + 16, little)? as u64,
            )
        };
        let range = checked_range(bytes, offset, size)?;
        let observed_size = (size as usize).min(MAX_INTERPRETER_BYTES);
        let source = &bytes[offset as usize..offset as usize + observed_size];
        let terminator = source.iter().position(|byte| *byte == 0);
        let display_bytes = terminator.map(|end| &source[..end]).unwrap_or(source);
        let malformed = terminator.is_none() || size as usize > MAX_INTERPRETER_BYTES;
        values.push(Name {
            display: String::from_utf8_lossy(display_bytes).into_owned(),
            bytes_base64: Some(base64(display_bytes)),
            location: Some(range),
            unknown_reason: malformed.then(|| {
                if size as usize > MAX_INTERPRETER_BYTES {
                    "PT_INTERP exceeds the bounded observation size".into()
                } else {
                    "PT_INTERP is not NUL-terminated".into()
                }
            }),
        });
    }
    Ok(values)
}

fn dynamic_flags(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Option<DynamicFlags>, Error> {
    let mut dynamic = None;
    for index in 0..phnum {
        let p = phoff
            .checked_add(index.saturating_mul(phentsize))
            .ok_or(Error::Format("ELF program-header range overflowed"))?;
        let kind = u32e(bytes, p as usize, little)?;
        if kind == 2 {
            let (offset, size) = if bits == 64 {
                (
                    u64e(bytes, p as usize + 8, little)?,
                    u64e(bytes, p as usize + 32, little)?,
                )
            } else {
                (
                    u32e(bytes, p as usize + 4, little)? as u64,
                    u32e(bytes, p as usize + 16, little)? as u64,
                )
            };
            dynamic = Some((offset, size));
        }
    }
    let Some((offset, size)) = dynamic else {
        return Ok(None);
    };
    let entry_size = if bits == 64 { 16 } else { 8 };
    let end = offset
        .checked_add(size)
        .ok_or(Error::Format("ELF dynamic table range overflowed"))?;
    if size % entry_size != 0 || end > bytes.len() as u64 {
        return Ok(Some(DynamicFlags {
            entries: Vec::new(),
            malformed: true,
            unknown_reason: Some("truncated-or-misaligned-dynamic-table"),
        }));
    }
    let mut entries = Vec::new();
    let mut at = offset;
    let mut scanned_entries = 0usize;
    let mut terminated = false;
    while at < end && scanned_entries < 16_384 {
        scanned_entries += 1;
        let p = at as usize;
        let tag = if bits == 64 {
            u64e(bytes, p, little)?
        } else {
            u32e(bytes, p, little)? as u64
        };
        let value = if bits == 64 {
            u64e(bytes, p + 8, little)?
        } else {
            u32e(bytes, p + 4, little)? as u64
        };
        if tag == 0 {
            terminated = true;
            break;
        }
        if matches!(tag, 22 | 24 | 30 | 0x6ffffffb) {
            let (named_bits, unknown_bits) = dynamic_flag_bits(tag, value);
            entries.push(DynamicFlagEntry {
                tag: hex(tag),
                value: hex(value),
                named_bits,
                unknown_bits,
                location: checked_range(bytes, at, entry_size)?,
            });
        }
        at += entry_size;
    }
    let exceeded_bound = scanned_entries == 16_384 && at < end;
    let missing_terminator = !terminated && !exceeded_bound;
    Ok(Some(DynamicFlags {
        entries,
        malformed: exceeded_bound || missing_terminator,
        unknown_reason: if exceeded_bound {
            Some("dynamic-flag-entry-count-exceeded-bound")
        } else if missing_terminator {
            Some("dynamic-table-missing-null-terminator")
        } else {
            None
        },
    }))
}

fn dynamic_flag_bits(tag: u64, value: u64) -> (Vec<String>, Vec<String>) {
    if tag == 22 {
        return (vec!["DT_TEXTREL".to_owned()], Vec::new());
    }
    if tag == 24 {
        return (vec!["DT_BIND_NOW".to_owned()], Vec::new());
    }
    let names: &[(u64, &str)] = if tag == 30 {
        &[
            (1, "DF_ORIGIN"),
            (2, "DF_SYMBOLIC"),
            (4, "DF_TEXTREL"),
            (8, "DF_BIND_NOW"),
            (16, "DF_STATIC_TLS"),
        ]
    } else {
        &[
            (1, "DF_1_NOW"),
            (2, "DF_1_GLOBAL"),
            (4, "DF_1_GROUP"),
            (8, "DF_1_NODELETE"),
            (16, "DF_1_LOADFLTR"),
            (32, "DF_1_INITFIRST"),
            (64, "DF_1_NOOPEN"),
            (128, "DF_1_ORIGIN"),
            (256, "DF_1_DIRECT"),
            (512, "DF_1_TRANS"),
            (1024, "DF_1_INTERPOSE"),
            (2048, "DF_1_NODEFLIB"),
            (4096, "DF_1_NODUMP"),
            (8192, "DF_1_CONFALT"),
            (16384, "DF_1_ENDFILTEE"),
            (32768, "DF_1_DISPRELDNE"),
            (65536, "DF_1_DISPRELPND"),
            (1 << 20, "DF_1_NODIRECT"),
            (1 << 21, "DF_1_IGNMULDEF"),
            (1 << 22, "DF_1_NOKSYMS"),
            (1 << 23, "DF_1_NOHDR"),
            (1 << 26, "DF_1_EDITED"),
        ]
    };
    let known = names.iter().fold(0, |mask, (bit, _)| mask | bit);
    let named = names
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect();
    let unknown = if value & !known == 0 {
        Vec::new()
    } else {
        vec![hex(value & !known)]
    };
    (named, unknown)
}

fn dynamic_string_tags(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Option<Vec<DynamicStringTag>>, Error> {
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..phnum {
        let p = phoff
            .checked_add(index.saturating_mul(phentsize))
            .ok_or(Error::Format("ELF program-header range overflowed"))?;
        let at = p as usize;
        let kind = u32e(bytes, at, little)?;
        let (offset, address, size) = if bits == 64 {
            (
                u64e(bytes, at + 8, little)?,
                u64e(bytes, at + 16, little)?,
                u64e(bytes, at + 32, little)?,
            )
        } else {
            (
                u32e(bytes, at + 4, little)? as u64,
                u32e(bytes, at + 8, little)? as u64,
                u32e(bytes, at + 16, little)? as u64,
            )
        };
        if kind == 1 {
            loads.push((address, size, offset));
        } else if kind == 2 {
            dynamic = Some((offset, size));
        }
    }
    let Some((dynamic_offset, dynamic_size)) = dynamic else {
        return Ok(None);
    };
    let entry_size = if bits == 64 { 16 } else { 8 };
    if dynamic_size % entry_size != 0 {
        return Ok(Some(Vec::new()));
    }
    let dynamic_end = dynamic_offset
        .checked_add(dynamic_size)
        .ok_or(Error::Format("ELF dynamic table range overflowed"))?;
    if dynamic_end > bytes.len() as u64 {
        return Ok(Some(Vec::new()));
    }
    let mut strtab = None;
    let mut strsz = None;
    let mut raw_entries = Vec::new();
    let mut at = dynamic_offset;
    while at < dynamic_end && raw_entries.len() < 16_384 {
        let p = at as usize;
        let tag = if bits == 64 {
            u64e(bytes, p, little)?
        } else {
            u32e(bytes, p, little)? as u64
        };
        let value = if bits == 64 {
            u64e(bytes, p + 8, little)?
        } else {
            u32e(bytes, p + 4, little)? as u64
        };
        if tag == 0 {
            break;
        }
        if tag == 5 {
            strtab = Some(value);
        } else if tag == 10 {
            strsz = Some(value);
        } else if is_dynamic_string_tag(tag) {
            raw_entries.push((tag, value, at));
        }
        at += entry_size;
    }
    if raw_entries.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let Some((strtab, strsz)) = strtab.zip(strsz) else {
        return Ok(Some(
            raw_entries
                .into_iter()
                .map(|(tag, value, entry)| DynamicStringTag {
                    tag: hex(tag),
                    tag_name: dynamic_string_tag_name(tag),
                    string_offset: hex(value),
                    value: None,
                    string_location: None,
                    entry_location: checked_range(bytes, entry, entry_size).unwrap_or(Range {
                        offset: hex(entry),
                        bytes: hex(entry_size),
                    }),
                    malformed: true,
                    unknown_reason: Some("dynamic-string-table-unavailable"),
                })
                .collect(),
        ));
    };
    let Some(string_base) = mapped_dynamic_offset(&loads, strtab, strsz) else {
        return Ok(Some(
            raw_entries
                .into_iter()
                .map(|(tag, value, entry)| DynamicStringTag {
                    tag: hex(tag),
                    tag_name: dynamic_string_tag_name(tag),
                    string_offset: hex(value),
                    value: None,
                    string_location: None,
                    entry_location: checked_range(bytes, entry, entry_size).unwrap_or(Range {
                        offset: hex(entry),
                        bytes: hex(entry_size),
                    }),
                    malformed: true,
                    unknown_reason: Some("dynamic-string-table-unmapped"),
                })
                .collect(),
        ));
    };
    let mut out = Vec::new();
    for (tag, value, entry) in raw_entries {
        let entry_location = checked_range(bytes, entry, entry_size)?;
        if value >= strsz {
            out.push(DynamicStringTag {
                tag: hex(tag),
                tag_name: dynamic_string_tag_name(tag),
                string_offset: hex(value),
                value: None,
                string_location: None,
                entry_location,
                malformed: true,
                unknown_reason: Some("dynamic-string-offset-out-of-range"),
            });
            continue;
        }
        let string_offset = string_base + value;
        let Some(end) = string_offset.checked_add(strsz - value) else {
            out.push(DynamicStringTag {
                tag: hex(tag),
                tag_name: dynamic_string_tag_name(tag),
                string_offset: hex(value),
                value: None,
                string_location: None,
                entry_location,
                malformed: true,
                unknown_reason: Some("dynamic-string-range-overflow"),
            });
            continue;
        };
        let end = end.min(bytes.len() as u64);
        let data = &bytes[string_offset as usize..end as usize];
        let Some(nul) = data.iter().position(|byte| *byte == 0) else {
            out.push(DynamicStringTag {
                tag: hex(tag),
                tag_name: dynamic_string_tag_name(tag),
                string_offset: hex(value),
                value: None,
                string_location: Some(Range {
                    offset: hex(string_offset),
                    bytes: hex(data.len() as u64),
                }),
                entry_location,
                malformed: true,
                unknown_reason: Some("dynamic-string-missing-terminator"),
            });
            continue;
        };
        out.push(DynamicStringTag {
            tag: hex(tag),
            tag_name: dynamic_string_tag_name(tag),
            string_offset: hex(value),
            value: Some(String::from_utf8_lossy(&data[..nul]).into_owned()),
            string_location: Some(Range {
                offset: hex(string_offset),
                bytes: hex((nul + 1) as u64),
            }),
            entry_location,
            malformed: false,
            unknown_reason: None,
        });
    }
    Ok(Some(out))
}

fn is_dynamic_string_tag(tag: u64) -> bool {
    matches!(
        tag,
        1 | 14 | 15 | 29 | 34 | 0x6ffffefb | 0x6ffffefc | 0x7ffffffd | 0x7fffffff
    )
}

fn dynamic_string_tag_name(tag: u64) -> &'static str {
    match tag {
        1 => "DT_NEEDED",
        14 => "DT_SONAME",
        15 => "DT_RPATH",
        29 => "DT_RUNPATH",
        34 => "DT_CONFIG",
        0x6ffffefb => "DT_AUDIT",
        0x6ffffefc => "DT_DEPAUDIT",
        0x7ffffffd => "DT_AUXILIARY",
        0x7fffffff => "DT_FILTER",
        _ => "DT_UNKNOWN",
    }
}

fn validate_relocation_symbol_index(
    sections: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    symbol_table_index: usize,
    symbol_index: u64,
) -> Result<(), Error> {
    if symbol_index == 0 {
        return Ok(());
    }
    let Some(symbol_table) = sections.get(symbol_table_index) else {
        return Err(Error::Format(
            "ELF relocation references a missing symbol table",
        ));
    };
    if symbol_table.0 != 2 && symbol_table.0 != 11 {
        return Err(Error::Format(
            "ELF relocation link does not identify a symbol table",
        ));
    }
    if symbol_table.8 == 0 || symbol_table.4 % symbol_table.8 != 0 {
        return Err(Error::Format(
            "ELF relocation references a malformed symbol table",
        ));
    }
    if symbol_index >= symbol_table.4 / symbol_table.8 {
        return Err(Error::Format("ELF relocation references a missing symbol"));
    }
    Ok(())
}

fn validate_relocation_target_section(
    image_type: u16,
    target_section_index: usize,
    section_count: usize,
) -> Result<(), Error> {
    if image_type == 1 && target_section_index >= section_count {
        return Err(Error::Format(
            "ELF relocation references a missing target section",
        ));
    }
    Ok(())
}

fn validate_symbol_string_table(
    sections: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    string_table_index: usize,
) -> Result<(u64, u64), Error> {
    let Some(string_table) = sections.get(string_table_index) else {
        return Err(Error::Format(
            "ELF symbol table links to a missing string table",
        ));
    };
    if string_table.0 != 3 {
        return Err(Error::Format(
            "ELF symbol table links to an invalid string table",
        ));
    }
    Ok((string_table.3, string_table.4))
}

fn validate_symbol_table_layout(
    entry_size: u64,
    table_size: u64,
    minimum_entry_size: u64,
    format_name: &'static str,
) -> Result<(), Error> {
    if entry_size < minimum_entry_size {
        return Err(Error::Format(format_name));
    }
    if table_size % entry_size != 0 {
        return Err(Error::Format("ELF symbol table size is not entry-aligned"));
    }
    Ok(())
}

fn notes_from_segments(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Vec<Note>, Error> {
    let mut notes = Vec::new();
    for index in 0..phnum {
        let p = (phoff + index * phentsize) as usize;
        let segment_type = u32e(bytes, p, little)?;
        const PT_NOTE: u32 = 4;
        const PT_GNU_PROPERTY: u32 = 0x6474_e553;
        if segment_type != PT_NOTE && segment_type != PT_GNU_PROPERTY {
            continue;
        }
        let (off, size) = if bits == 64 {
            (u64e(bytes, p + 8, little)?, u64e(bytes, p + 32, little)?)
        } else {
            (
                u32e(bytes, p + 4, little)? as u64,
                u32e(bytes, p + 16, little)? as u64,
            )
        };
        let end = off
            .checked_add(size)
            .ok_or(Error::Format("ELF note range overflow"))?;
        if end > bytes.len() as u64 {
            return Err(Error::Format(
                "ELF note range lies outside the selected snapshot",
            ));
        }
        let descriptor_alignment = if segment_type == PT_GNU_PROPERTY {
            8
        } else {
            4
        };
        let name_alignment = 4;
        let mut at = off;
        while at < end {
            if end - at < 12 {
                notes.push(Note {
                    segment_index: index as usize,
                    name: String::new(),
                    note_type: 0,
                    descriptor_base64: String::new(),
                    location: Range {
                        offset: hex(at),
                        bytes: hex(end - at),
                    },
                    malformed: true,
                    decoded: None,
                });
                break;
            }
            let q = at as usize;
            let ns = u32e(bytes, q, little)? as u64;
            let ds = u32e(bytes, q + 4, little)? as u64;
            let typ = u32e(bytes, q + 8, little)?;
            let name_start = at + 12;
            let desc_start =
                name_start + (ns + name_alignment - 1) / name_alignment * name_alignment;
            let next = desc_start
                + (ds + descriptor_alignment - 1) / descriptor_alignment * descriptor_alignment;
            if next > end {
                notes.push(Note {
                    segment_index: index as usize,
                    name: String::new(),
                    note_type: typ,
                    descriptor_base64: String::new(),
                    location: Range {
                        offset: hex(at),
                        bytes: hex(end - at),
                    },
                    malformed: true,
                    decoded: None,
                });
                break;
            }
            let name_bytes = &bytes[name_start as usize..(name_start + ns).min(end) as usize];
            let desc = &bytes[desc_start as usize..(desc_start + ds) as usize];
            let decoded = decode_core_note(name_bytes, desc, typ, little, bits);
            notes.push(Note {
                segment_index: index as usize,
                name: String::from_utf8_lossy(name_bytes)
                    .trim_end_matches('\0')
                    .into(),
                note_type: typ,
                descriptor_base64: base64(desc),
                location: checked_range(bytes, at, next - at)?,
                malformed: false,
                decoded,
            });
            at = next;
        }
    }
    Ok(notes)
}

fn notes_from_sections(
    bytes: &[u8],
    sections: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    little: bool,
    bits: u8,
) -> Result<Vec<Note>, Error> {
    let mut notes = Vec::new();
    for (section_index, section) in sections
        .iter()
        .enumerate()
        .filter(|(_, section)| section.0 == 7)
    {
        let alignment = if section.7 == 0 { 4 } else { section.7 };
        let start = section.3;
        let end = start
            .checked_add(section.4)
            .ok_or(Error::Format("ELF note section range overflow"))?;
        if end > bytes.len() as u64 {
            notes.push(Note {
                segment_index: section_index,
                name: String::new(),
                note_type: 0,
                descriptor_base64: String::new(),
                location: Range {
                    offset: hex(start),
                    bytes: hex(section.4),
                },
                malformed: true,
                decoded: None,
            });
            continue;
        }
        let mut at = start;
        while at < end {
            let record_start = at;
            if end - at < 12 {
                notes.push(Note {
                    segment_index: section_index,
                    name: String::new(),
                    note_type: 0,
                    descriptor_base64: String::new(),
                    location: checked_range(bytes, at, end - at)?,
                    malformed: true,
                    decoded: None,
                });
                break;
            }
            let name_size = u32e(bytes, at as usize, little)? as u64;
            let descriptor_size = u32e(bytes, at as usize + 4, little)? as u64;
            let note_type = u32e(bytes, at as usize + 8, little)?;
            let name_start = at + 12;
            let descriptor_start = name_start
                .checked_add((name_size + alignment - 1) & !(alignment - 1))
                .ok_or(Error::Format("ELF note name range overflow"))?;
            let next = descriptor_start
                .checked_add((descriptor_size + alignment - 1) & !(alignment - 1))
                .ok_or(Error::Format("ELF note descriptor range overflow"))?;
            if next > end {
                notes.push(Note {
                    segment_index: section_index,
                    name: String::new(),
                    note_type,
                    descriptor_base64: String::new(),
                    location: checked_range(bytes, record_start, end - record_start)?,
                    malformed: true,
                    decoded: None,
                });
                break;
            }
            let name_bytes = &bytes
                [name_start as usize..(name_start + name_size).min(descriptor_start) as usize];
            let descriptor =
                &bytes[descriptor_start as usize..(descriptor_start + descriptor_size) as usize];
            notes.push(Note {
                segment_index: section_index,
                name: String::from_utf8_lossy(name_bytes)
                    .trim_end_matches('\0')
                    .into(),
                note_type,
                descriptor_base64: base64(descriptor),
                location: checked_range(bytes, record_start, next - record_start)?,
                malformed: false,
                decoded: decode_core_note(name_bytes, descriptor, note_type, little, bits),
            });
            at = next;
        }
    }
    Ok(notes)
}

fn section_groups(
    bytes: &[u8],
    sections: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    symbols: &[Symbol],
    little: bool,
) -> Result<Vec<SectionGroup>, Error> {
    let mut groups = Vec::new();
    for (section_index, section) in sections.iter().enumerate() {
        if section.0 != 17 {
            continue;
        }
        let location = checked_range(bytes, section.3, section.4)?;
        let mut malformed = false;
        let mut unknown_reason = None;
        if section.4 < 4 || section.4 % 4 != 0 {
            malformed = true;
            unknown_reason = Some("truncated-or-misaligned-group-table");
        }
        let flags = if section.4 >= 4 {
            u32e(bytes, section.3 as usize, little)?
        } else {
            0
        };
        let mut members = Vec::new();
        if !malformed {
            for entry in 1..(section.4 / 4) {
                members.push(u32e(bytes, (section.3 + entry * 4) as usize, little)? as usize);
            }
            if members.iter().any(|member| *member >= sections.len()) {
                malformed = true;
                unknown_reason = Some("group-member-index-out-of-range");
            }
        }
        let signature_symbol_index = section.6;
        let signature_name = symbols
            .iter()
            .find(|symbol| {
                symbol.table_index == section.5 && symbol.entry_index == signature_symbol_index
            })
            .map(|symbol| Name {
                display: symbol.name.display.clone(),
                bytes_base64: symbol.name.bytes_base64.clone(),
                location: symbol.name.location.clone(),
                unknown_reason: symbol.name.unknown_reason.clone(),
            });
        if signature_name.is_none() {
            unknown_reason.get_or_insert("group-signature-symbol-unresolved");
        }
        groups.push(SectionGroup {
            section_index,
            flags: hex(flags as u64),
            signature_symbol_table: section.5,
            signature_symbol_index,
            signature_name,
            member_section_indices: members,
            location,
            malformed,
            unknown_reason,
        });
    }
    Ok(groups)
}

fn debug_links_from_sections(
    bytes: &[u8],
    sections: &[Section],
    little: bool,
) -> Result<Vec<DebugLink>, Error> {
    let mut links = Vec::new();
    for section in sections {
        let kind = match section.name.display.as_str() {
            ".gnu_debuglink" => "gnu-debuglink",
            ".gnu_debugaltlink" => "gnu-debugaltlink",
            _ => continue,
        };
        let offset = u64::from_str_radix(section.offset.trim_start_matches("0x"), 16)
            .map_err(|_| Error::Format("ELF debug-link offset is not numeric"))?;
        let size = u64::from_str_radix(section.size.trim_start_matches("0x"), 16)
            .map_err(|_| Error::Format("ELF debug-link size is not numeric"))?;
        let location = checked_range(bytes, offset, size)?;
        let data = &bytes[offset as usize..(offset + size) as usize];
        let nul = data.iter().position(|byte| *byte == 0);
        let mut malformed = false;
        let mut unknown_reason = None;
        let filename_end = nul.unwrap_or(data.len());
        if nul.is_none() {
            malformed = true;
            unknown_reason = Some("missing-null-terminated-filename");
        }
        let filename_bytes = &data[..filename_end];
        let aligned = filename_end.saturating_add(1).saturating_add(3) & !3;
        if filename_bytes.is_empty() {
            malformed = true;
            unknown_reason.get_or_insert("empty-debug-link-filename");
        }
        if aligned > data.len() {
            malformed = true;
            unknown_reason.get_or_insert("truncated-alignment-padding");
        }
        let padding_end = aligned.min(data.len());
        let padding_start = filename_end.saturating_add(1).min(padding_end);
        if data[padding_start..padding_end]
            .iter()
            .any(|byte| *byte != 0)
        {
            malformed = true;
            unknown_reason = Some("nonzero-alignment-padding");
        }
        let (crc32, crc32_location, build_id_base64, build_id_location) = if kind == "gnu-debuglink"
        {
            if aligned.saturating_add(4) > data.len() {
                malformed = true;
                unknown_reason.get_or_insert("missing-debuglink-crc32");
                (None, None, None, None)
            } else {
                let crc = u32e(data, aligned, little)?;
                (
                    Some(hex(crc as u64)),
                    Some(Range {
                        offset: hex(offset + aligned as u64),
                        bytes: hex(4),
                    }),
                    None,
                    None,
                )
            }
        } else if aligned >= data.len() {
            malformed = true;
            unknown_reason.get_or_insert("missing-debugaltlink-build-id");
            (None, None, None, None)
        } else {
            (
                None,
                None,
                Some(base64(&data[aligned..])),
                Some(Range {
                    offset: hex(offset + aligned as u64),
                    bytes: hex((data.len() - aligned) as u64),
                }),
            )
        };
        links.push(DebugLink {
            kind,
            filename: String::from_utf8_lossy(filename_bytes).into_owned(),
            filename_base64: base64(filename_bytes),
            crc32,
            crc32_location,
            build_id_base64,
            build_id_location,
            location,
            malformed,
            unknown_reason,
        });
    }
    Ok(links)
}

fn decode_core_note(
    name: &[u8],
    descriptor: &[u8],
    note_type: u32,
    little: bool,
    bits: u8,
) -> Option<DecodedNote> {
    let owner = name.strip_suffix(&[0]).unwrap_or(name);
    if owner == b"GNU" && note_type == 3 {
        return Some(DecodedNote::GnuBuildId {
            build_id_base64: base64(descriptor),
        });
    }
    if owner == b"GNU" && note_type == 1 {
        return Some(decode_gnu_abi_tag(descriptor, little));
    }
    if owner == b"GNU" && note_type == 5 {
        return Some(decode_gnu_properties(descriptor, little));
    }
    if owner == b"CORE" && note_type == 0x46494c45 {
        return Some(decode_nt_file(descriptor, little, bits));
    }
    if owner == b"CORE" && note_type == 1 {
        return Some(decode_nt_prstatus(descriptor, little, bits));
    }
    if owner == b"CORE" && note_type == 6 {
        return Some(decode_nt_auxv(descriptor, little, bits));
    }
    if owner == b"CORE" && note_type == 0x53494749 {
        return Some(decode_nt_siginfo(descriptor, little));
    }
    if owner == b"CORE" && note_type == 2 {
        return Some(decode_nt_fpregset(descriptor));
    }
    if owner == b"CORE" && note_type == 3 {
        return Some(decode_nt_prpsinfo(descriptor, little, bits));
    }
    if owner == b"CORE" && note_type == 4 {
        return Some(decode_nt_taskstruct(descriptor));
    }
    None
}

fn decode_nt_taskstruct(descriptor: &[u8]) -> DecodedNote {
    DecodedNote::NtTaskStruct {
        byte_length: descriptor.len() as u64,
        malformed: descriptor.is_empty(),
    }
}

fn decode_nt_prpsinfo(descriptor: &[u8], little: bool, bits: u8) -> DecodedNote {
    let (pid_offset, command_offset): (usize, usize) = if bits == 64 { (24, 40) } else { (16, 20) };
    let pid = pid_offset
        .checked_add(4)
        .filter(|end| *end <= descriptor.len())
        .and_then(|_| u32e(descriptor, pid_offset, little).ok())
        .map(|value| value as i32 as i64);
    let command = command_offset
        .checked_add(16)
        .filter(|end| *end <= descriptor.len())
        .map(|_| {
            let bytes = &descriptor[command_offset..command_offset + 16];
            String::from_utf8_lossy(bytes)
                .trim_end_matches('\0')
                .to_owned()
        });
    let malformed = pid.is_none() || command.is_none();
    DecodedNote::NtPrPsInfo {
        pid,
        command,
        malformed,
    }
}

fn decode_nt_fpregset(descriptor: &[u8]) -> DecodedNote {
    DecodedNote::NtFpRegSet {
        byte_length: descriptor.len() as u64,
        malformed: descriptor.is_empty(),
    }
}

fn decode_nt_siginfo(descriptor: &[u8], little: bool) -> DecodedNote {
    let read = |offset: usize| -> Option<i64> {
        if offset.checked_add(4)? > descriptor.len() {
            return None;
        }
        Some(u32e(descriptor, offset, little).ok()? as i32 as i64)
    };
    DecodedNote::NtSigInfo {
        signal: read(0),
        errno: read(4),
        code: read(8),
        malformed: descriptor.len() < 12,
    }
}

fn decode_nt_auxv(descriptor: &[u8], little: bool, bits: u8) -> DecodedNote {
    let width = if bits == 64 { 16 } else { 8 };
    let complete_bytes = descriptor.len() / width * width;
    let mut entries = Vec::new();
    let mut terminated = false;

    for offset in (0..complete_bytes).step_by(width).take(4096) {
        let (kind, value) = if bits == 64 {
            (
                u64e(descriptor, offset, little).unwrap_or(0),
                u64e(descriptor, offset + 8, little).unwrap_or(0),
            )
        } else {
            (
                u32e(descriptor, offset, little).unwrap_or(0) as u64,
                u32e(descriptor, offset + 4, little).unwrap_or(0) as u64,
            )
        };
        entries.push(CoreAuxvEntry {
            kind: hex(kind),
            value: hex(value),
        });
        if kind == 0 {
            terminated = true;
            break;
        }
    }

    let malformed = descriptor.len() % width != 0 || !terminated || complete_bytes / width > 4096;
    DecodedNote::NtAuxv { entries, malformed }
}

fn decode_gnu_abi_tag(descriptor: &[u8], little: bool) -> DecodedNote {
    let malformed = descriptor.len() != 16;
    let read = |offset: usize| u32e(descriptor, offset, little).unwrap_or(0);
    let os = match read(0) {
        0 => "GNU_ABI_TAG_OS_LINUX".to_owned(),
        1 => "GNU_ABI_TAG_OS_HURD".to_owned(),
        2 => "GNU_ABI_TAG_OS_SOLARIS".to_owned(),
        3 => "GNU_ABI_TAG_OS_FREEBSD".to_owned(),
        value => format!("unknown({})", hex(value as u64)),
    };
    DecodedNote::GnuAbiTag {
        os,
        major: hex(read(4) as u64),
        minor: hex(read(8) as u64),
        subminor: hex(read(12) as u64),
        malformed,
    }
}

fn decode_gnu_properties(descriptor: &[u8], little: bool) -> DecodedNote {
    let mut properties = Vec::new();
    let mut offset = 0usize;
    let mut malformed = false;
    while offset < descriptor.len() && properties.len() < 16_384 {
        if descriptor.len() - offset < 8 {
            malformed = true;
            break;
        }
        let property_type = u32e(descriptor, offset, little).unwrap_or(0);
        let data_size = u32e(descriptor, offset + 4, little).unwrap_or(0) as usize;
        if property_type == 0 && data_size == 0 {
            if descriptor[offset..].iter().all(|byte| *byte == 0) {
                break;
            }
            malformed = true;
            break;
        }
        let data_start = offset + 8;
        let Some(data_end) = data_start.checked_add(data_size) else {
            malformed = true;
            break;
        };
        if data_end > descriptor.len() {
            malformed = true;
            break;
        }
        let data = &descriptor[data_start..data_end];
        let (named_bits, unknown_bits) = gnu_property_bits(property_type, data, little);
        let property_malformed = !matches!(data.len(), 4 | 8);
        let aligned_size = (data_size.saturating_add(7)) & !7;
        let property_end = data_start.saturating_add(aligned_size);
        properties.push(GnuPropertyValue {
            property_type,
            data_base64: base64(data),
            named_bits,
            unknown_bits,
            descriptor_offset: hex(data_start as u64),
            location: Range {
                offset: hex(offset as u64),
                bytes: hex(property_end.saturating_sub(offset) as u64),
            },
            malformed: property_malformed,
        });
        if property_malformed {
            malformed = true;
        }
        let Some(next) = data_start.checked_add(aligned_size) else {
            malformed = true;
            break;
        };
        if next > descriptor.len() {
            malformed = true;
            break;
        }
        if next <= offset {
            malformed = true;
            break;
        }
        offset = next;
    }
    if properties.len() == 16_384 && offset < descriptor.len() {
        malformed = true;
    }
    DecodedNote::GnuProperty {
        properties,
        malformed,
    }
}

fn gnu_property_bits(property_type: u32, data: &[u8], little: bool) -> (Vec<String>, Vec<String>) {
    let value = match data.len() {
        4 => u32e(data, 0, little).unwrap_or(0) as u64,
        8 => u64e(data, 0, little).unwrap_or(0),
        _ => return (Vec::new(), Vec::new()),
    };
    let names: &[(u64, &str)] = match property_type {
        0xc0000002 => &[(1, "x86-ibt"), (2, "x86-shstk")],
        0xc0000000 => &[(1, "aarch64-bti"), (2, "aarch64-pac")],
        0xc0008000 | 0xc0008001 => &[
            (1, "x86-486"),
            (2, "x86-586"),
            (4, "x86-686"),
            (8, "x86-sse"),
            (16, "x86-sse2"),
            (32, "x86-sse3"),
            (64, "x86-ssse3"),
            (128, "x86-sse4.1"),
            (256, "x86-sse4.2"),
            (512, "x86-avx"),
            (1024, "x86-avx2"),
            (2048, "x86-fma"),
            (4096, "x86-avx512f"),
            (8192, "x86-avx512bw"),
            (16384, "x86-avx512cd"),
            (32768, "x86-avx512dq"),
            (65536, "x86-avx512er"),
            (131072, "x86-avx512pf"),
            (262144, "x86-avx512vl"),
        ],
        0xc0008002 | 0xc0008003 => &[(1, "x86-feature2-x86"), (2, "x86-feature2-x87")],
        _ => &[],
    };
    let known_mask = names.iter().fold(0, |mask, (bit, _)| mask | bit);
    let named = names
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect();
    let unknown = if known_mask == 0 {
        if value == 0 {
            Vec::new()
        } else {
            vec![hex(value)]
        }
    } else {
        let remaining = value & !known_mask;
        if remaining == 0 {
            Vec::new()
        } else {
            vec![hex(remaining)]
        }
    };
    (named, unknown)
}

fn core_word(descriptor: &[u8], offset: usize, width: usize, little: bool) -> Option<u64> {
    let end = offset.checked_add(width)?;
    if end > descriptor.len() {
        return None;
    }
    Some(if width == 8 {
        u64e(descriptor, offset, little).ok()?
    } else {
        u32e(descriptor, offset, little).ok()? as u64
    })
}

fn decode_nt_file(descriptor: &[u8], little: bool, bits: u8) -> DecodedNote {
    let width = if bits == 64 { 8 } else { 4 };
    let Some(count) = core_word(descriptor, 0, width, little) else {
        return DecodedNote::NtFile {
            page_size: 0,
            mappings: Vec::new(),
            malformed: true,
        };
    };
    let page_size = core_word(descriptor, width, width, little).unwrap_or(0);
    let bounded_count = count.min(16_384);
    let records_end = width
        .checked_mul(2)
        .and_then(|value| value.checked_add(bounded_count as usize * width * 3));
    let Some(records_end) = records_end else {
        return DecodedNote::NtFile {
            page_size,
            mappings: Vec::new(),
            malformed: true,
        };
    };
    let mut mappings = Vec::new();
    for index in 0..bounded_count as usize {
        let offset = width * 2 + index * width * 3;
        let (Some(start), Some(end), Some(file_offset)) = (
            core_word(descriptor, offset, width, little),
            core_word(descriptor, offset + width, width, little),
            core_word(descriptor, offset + width * 2, width, little),
        ) else {
            break;
        };
        mappings.push(CoreFileMapping {
            start: hex(start),
            end: hex(end),
            file_offset: hex(file_offset),
            path: String::new(),
        });
    }
    let mut path_offset = records_end.min(descriptor.len());
    for mapping in &mut mappings {
        if path_offset >= descriptor.len() {
            break;
        }
        let tail = &descriptor[path_offset..];
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(tail.len());
        mapping.path = String::from_utf8_lossy(&tail[..length]).into_owned();
        path_offset = path_offset.saturating_add(length.saturating_add(1));
    }
    DecodedNote::NtFile {
        page_size,
        mappings,
        malformed: count > 16_384 || records_end > descriptor.len(),
    }
}

fn decode_nt_prstatus(descriptor: &[u8], little: bool, bits: u8) -> DecodedNote {
    let signal = core_word(descriptor, 0, 4, little);
    let identity_offset = if bits == 64 { 32 } else { 24 };
    let pid = core_word(descriptor, identity_offset, 4, little);
    let ppid = core_word(descriptor, identity_offset + 4, 4, little);
    DecodedNote::NtPrStatus {
        signal,
        pid,
        ppid,
        tid: None,
        malformed: signal.is_none() || pid.is_none(),
    }
}

fn gnu_version_names(
    bytes: &[u8],
    raw: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    little: bool,
) -> Result<std::collections::BTreeMap<u16, String>, Error> {
    let mut names = std::collections::BTreeMap::new();
    for section in raw
        .iter()
        .filter(|s| s.0 == 0x6ffffffd || s.0 == 0x6ffffffe)
    {
        let Some(strings) = raw.get(section.5).filter(|s| s.0 == 3) else {
            continue;
        };
        let end = section.3.saturating_add(section.4);
        if end > bytes.len() as u64 {
            continue;
        }
        let mut at = section.3;
        let mut records = 0usize;
        while records < 16_384 {
            let header_size = if section.0 == 0x6ffffffd { 20 } else { 16 };
            if at.saturating_add(header_size) > end {
                break;
            }

            let (index, aux_offset, next_offset) = if section.0 == 0x6ffffffd {
                let index = u16e(bytes, at as usize + 4, little)?;
                let aux_offset = u32e(bytes, at as usize + 12, little)? as u64;
                let next_offset = u32e(bytes, at as usize + 16, little)? as u64;
                (index, aux_offset, next_offset)
            } else {
                let aux_offset = u32e(bytes, at as usize + 8, little)? as u64;
                let next_offset = u32e(bytes, at as usize + 12, little)? as u64;
                (0, aux_offset, next_offset)
            };

            let aux = at.saturating_add(aux_offset);
            if aux.saturating_add(8) > end {
                break;
            }

            if section.0 == 0x6ffffffe {
                let mut aux_at = aux;
                let mut aux_records = 0usize;
                while aux_records < 16_384 && aux_at.saturating_add(16) <= end {
                    let version_index = u16e(bytes, aux_at as usize + 6, little)?;
                    let name_offset = u32e(bytes, aux_at as usize + 8, little)? as u64;
                    if let Some(name) = version_name(bytes, &(strings.3, strings.4), name_offset)? {
                        names.insert(version_index, name);
                    }
                    let next = u32e(bytes, aux_at as usize + 12, little)? as u64;
                    aux_records += 1;
                    if next == 0 {
                        break;
                    }
                    let next_at = aux_at.saturating_add(next);
                    if next_at <= aux_at || next_at >= end {
                        break;
                    }
                    aux_at = next_at;
                }
            } else {
                let name_offset = u32e(bytes, aux as usize, little)? as u64;
                if let Some(name) = version_name(bytes, &(strings.3, strings.4), name_offset)? {
                    names.insert(index, name);
                }
            }

            records += 1;
            if next_offset == 0 {
                break;
            }
            let next = at.saturating_add(next_offset);
            if next <= at || next >= end {
                break;
            }
            at = next;
        }
    }
    Ok(names)
}

fn version_name(bytes: &[u8], strings: &(u64, u64), offset: u64) -> Result<Option<String>, Error> {
    if offset >= strings.1 {
        return Ok(None);
    }
    Ok(Some(
        string_name(bytes, Some((strings.0, strings.1)), offset as u32)?.display,
    ))
}

fn gnu_version_tables(
    bytes: &[u8],
    raw: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    little: bool,
) -> Result<Option<SymbolVersionTables>, Error> {
    let mut definitions = Vec::new();
    let mut requirements = Vec::new();
    let mut malformed = false;

    for section in raw
        .iter()
        .filter(|section| section.0 == 0x6ffffffd || section.0 == 0x6ffffffe)
    {
        let Some(strings) = raw.get(section.5).filter(|string| string.0 == 3) else {
            malformed = true;
            continue;
        };
        let Some(end) = section.3.checked_add(section.4) else {
            malformed = true;
            continue;
        };
        if end > bytes.len() as u64 {
            malformed = true;
            continue;
        }

        let mut current = section.3;
        for _ in 0..16_384 {
            let header_size = if section.0 == 0x6ffffffd { 20 } else { 16 };
            if current.saturating_add(header_size) > end {
                malformed = true;
                break;
            }
            let location = match checked_range(bytes, current, header_size) {
                Ok(range) => range,
                Err(_) => {
                    malformed = true;
                    break;
                }
            };

            if section.0 == 0x6ffffffd {
                let index = u16e(bytes, current as usize + 4, little)?;
                let flags = u16e(bytes, current as usize + 2, little)?;
                let auxiliary = u32e(bytes, current as usize + 12, little)? as u64;
                let count = u16e(bytes, current as usize + 6, little)?;
                let mut names = Vec::new();
                let mut auxiliary_at = current.saturating_add(auxiliary);
                let mut record_malformed = false;
                for _ in 0..u64::from(count).min(16_384) {
                    if auxiliary_at.saturating_add(8) > end {
                        record_malformed = true;
                        break;
                    }
                    let name_offset = u32e(bytes, auxiliary_at as usize, little)? as u64;
                    if let Some(name) = version_name(bytes, &(strings.3, strings.4), name_offset)? {
                        names.push(name);
                    } else {
                        record_malformed = true;
                    }
                    let next = u32e(bytes, auxiliary_at as usize + 4, little)? as u64;
                    if next == 0 {
                        break;
                    }
                    let Some(next_at) = auxiliary_at.checked_add(next) else {
                        record_malformed = true;
                        break;
                    };
                    if next_at <= auxiliary_at || next_at >= end {
                        record_malformed = true;
                        break;
                    }
                    auxiliary_at = next_at;
                }
                definitions.push(SymbolVersionDefinition {
                    index,
                    flags,
                    auxiliary_names: names,
                    location,
                    malformed: record_malformed,
                });
                malformed |= record_malformed;
            } else {
                let file_offset = u32e(bytes, current as usize + 4, little)? as u64;
                let auxiliary = u32e(bytes, current as usize + 8, little)? as u64;
                let count = u16e(bytes, current as usize + 2, little)?;
                let file = version_name(bytes, &(strings.3, strings.4), file_offset)?;
                if file.is_none() {
                    malformed = true;
                }
                let mut names = Vec::new();
                let mut record_malformed = false;
                let mut auxiliary_at = current.saturating_add(auxiliary);
                for _ in 0..u64::from(count).min(16_384) {
                    if auxiliary_at.saturating_add(16) > end {
                        record_malformed = true;
                        break;
                    }
                    let name_offset = u32e(bytes, auxiliary_at as usize + 8, little)? as u64;
                    if let Some(name) = version_name(bytes, &(strings.3, strings.4), name_offset)? {
                        names.push(name);
                    } else {
                        record_malformed = true;
                    }
                    let next = u32e(bytes, auxiliary_at as usize + 12, little)? as u64;
                    if next == 0 {
                        break;
                    }
                    let Some(next_at) = auxiliary_at.checked_add(next) else {
                        record_malformed = true;
                        break;
                    };
                    if next_at <= auxiliary_at || next_at >= end {
                        record_malformed = true;
                        break;
                    }
                    auxiliary_at = next_at;
                }
                requirements.push(SymbolVersionRequirement {
                    file,
                    auxiliary_names: names,
                    location,
                    malformed: record_malformed,
                });
                malformed |= record_malformed;
            }

            let next_offset = if section.0 == 0x6ffffffd {
                u32e(bytes, current as usize + 16, little)? as u64
            } else {
                u32e(bytes, current as usize + 12, little)? as u64
            };
            if next_offset == 0 {
                break;
            }
            let Some(next) = current.checked_add(next_offset) else {
                malformed = true;
                break;
            };
            if next <= current || next >= end {
                malformed = true;
                break;
            }
            current = next;
        }
    }

    if definitions.is_empty() && requirements.is_empty() && !malformed {
        Ok(None)
    } else {
        Ok(Some(SymbolVersionTables {
            definitions,
            requirements,
            malformed,
        }))
    }
}

fn attach_section_versions(
    bytes: &[u8],
    raw: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    little: bool,
    symbols: &mut [Symbol],
) -> Result<(), Error> {
    let names = gnu_version_names(bytes, raw, little)?;
    for symbol in symbols {
        let Some(version) = raw
            .iter()
            .find(|s| s.0 == 0x6fffffff && s.5 == symbol.table_index)
        else {
            continue;
        };
        let offset = version.3.saturating_add(symbol.entry_index as u64 * 2);
        if offset.saturating_add(2) > version.3.saturating_add(version.4) {
            symbol.version_state = "malformed";
            continue;
        }
        let Some(location) = checked_range(bytes, offset, 2).ok() else {
            symbol.version_state = "malformed";
            continue;
        };
        let index = u16e(bytes, offset as usize, little)?;
        let version_index = index & 0x7fff;

        symbol.version_index = Some(index);
        symbol.version_location = Some(location);
        symbol.version_hidden = index & 0x8000 != 0;
        symbol.version = names.get(&version_index).cloned();
        symbol.version_state = if version_index == 0 {
            "unversioned"
        } else if symbol.version.is_some() {
            "resolved"
        } else {
            "unresolved"
        };
    }
    Ok(())
}

fn dynamic_symbols(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Vec<Symbol>, Error> {
    let mut loads = Vec::new();
    let mut dynamic = None;
    for i in 0..phnum {
        let p = (phoff + i * phentsize) as usize;
        let kind = u32e(bytes, p, little)?;
        let (off, va, size) = if bits == 64 {
            (
                u64e(bytes, p + 8, little)?,
                u64e(bytes, p + 16, little)?,
                u64e(bytes, p + 32, little)?,
            )
        } else {
            (
                u32e(bytes, p + 4, little)? as u64,
                u32e(bytes, p + 8, little)? as u64,
                u32e(bytes, p + 16, little)? as u64,
            )
        };
        if kind == 1 {
            loads.push((va, size, off));
        }
        if kind == 2 {
            dynamic = Some((off, size));
        }
    }
    let Some((off, size)) = dynamic else {
        return Ok(Vec::new());
    };
    let width = if bits == 64 { 16 } else { 8 };
    let mut symtab = None;
    let mut syment = if bits == 64 { 24 } else { 16 };
    let mut strtab = None;
    let mut strsz = None;
    let mut count = None;
    let mut gnu_hash = None;
    let mut versym = None;
    let mut verdef = None;
    let mut verdef_num = None;
    let mut verneed = None;
    let mut verneed_num = None;
    for at in (off..off.saturating_add(size)).step_by(width) {
        let p = at as usize;
        let tag = if bits == 64 {
            u64e(bytes, p, little)?
        } else {
            u32e(bytes, p, little)? as u64
        };
        let val = if bits == 64 {
            u64e(bytes, p + 8, little)?
        } else {
            u32e(bytes, p + 4, little)? as u64
        };
        if tag == 0 {
            break;
        }
        match tag {
            4 => {
                let hp = loads
                    .iter()
                    .find(|(v, s, _)| val >= *v && val < *v + s)
                    .map(|x| x.2 + (val - x.0));
                if let Some(hp) = hp {
                    if bits == 64 {
                        count = Some(u32e(bytes, hp as usize + 4, little)? as u64)
                    } else {
                        count = Some(u32e(bytes, hp as usize + 4, little)? as u64)
                    }
                }
            }
            6 => symtab = Some(val),
            10 => strsz = Some(val),
            5 => strtab = Some(val),
            11 => syment = val,
            0x6ffffef5 => gnu_hash = Some(val),
            0x6ffffff0 => versym = Some(val),
            0x6ffffffc => verdef = Some(val),
            0x6ffffffd => verdef_num = Some(val),
            0x6ffffffe => verneed = Some(val),
            0x6fffffff => verneed_num = Some(val),
            _ => {}
        }
    }
    let (Some(symtab), Some(strtab), Some(strsz)) = (symtab, strtab, strsz) else {
        return Ok(Vec::new());
    };
    if count.is_none() {
        if let Some(hash) = gnu_hash {
            if let Some((hv, hs, ho)) = loads
                .iter()
                .find(|(v, s, _)| hash >= *v && hash < v.saturating_add(*s))
            {
                let hp = (*ho + hash - *hv) as usize;
                let buckets = u32e(bytes, hp, little)? as u64;
                let symbol_offset = u32e(bytes, hp + 4, little)? as u64;
                let bloom = u32e(bytes, hp + 8, little)? as u64;
                let word = if bits == 64 { 8 } else { 4 };
                let bloom_bytes = bloom
                    .checked_mul(word)
                    .ok_or(Error::Format("GNU hash bloom filter overflow"))?;
                let bucket_bytes = buckets
                    .checked_mul(4)
                    .ok_or(Error::Format("GNU hash bucket table overflow"))?;
                let bucket_start = hp
                    .checked_add(
                        16usize
                            .checked_add(bloom_bytes as usize)
                            .ok_or(Error::Format("GNU hash table overflow"))?,
                    )
                    .ok_or(Error::Format("GNU hash table overflow"))?;
                let bucket_end = bucket_start
                    .checked_add(bucket_bytes as usize)
                    .ok_or(Error::Format("GNU hash table overflow"))?;
                if checked_dynamic_range(bytes, hp as u64, (bucket_end - hp) as u64).is_none() {
                    return Err(Error::Format("GNU hash bucket table is truncated"));
                }
                let mut maximum = symbol_offset;
                for bucket in 0..buckets.min(16_384) {
                    let value = u32e(bytes, bucket_start + bucket as usize * 4, little)? as u64;
                    if value < symbol_offset {
                        continue;
                    }
                    let chain =
                        bucket_start + buckets as usize * 4 + (value - symbol_offset) as usize * 4;
                    for step in 0..16_384usize {
                        if checked_dynamic_range(bytes, chain as u64 + step as u64 * 4, 4).is_none()
                        {
                            return Err(Error::Format("GNU hash chain table is truncated"));
                        }
                        let hash_value = u32e(bytes, chain + step * 4, little)?;
                        maximum = maximum.max(value + step as u64 + 1);
                        if hash_value & 1 != 0 {
                            break;
                        }
                    }
                }
                if maximum > symbol_offset {
                    count = Some(maximum);
                }
                let _ = hs;
            }
        }
    }
    let Some(count) = count else {
        return Ok(Vec::new());
    };
    let Some((sv, _ss, so)) = loads.iter().find(|(v, s, _)| {
        symtab >= *v && symtab.saturating_add(count.saturating_mul(syment)) <= v.saturating_add(*s)
    }) else {
        return Ok(Vec::new());
    };
    let symoff = *so + (symtab - *sv);
    let Some((tv, _, to)) = loads
        .iter()
        .find(|(v, s, _)| strtab >= *v && strtab.saturating_add(strsz) <= v.saturating_add(*s))
    else {
        return Ok(Vec::new());
    };
    let stroff = *to + (strtab - *tv);
    let mut out = Vec::new();
    for e in 0..count.min(16_384) {
        let p = (symoff + e * syment) as usize;
        let (name, value, size, info, other, shndx) = if bits == 64 {
            (
                u32e(bytes, p, little)?,
                u64e(bytes, p + 8, little)?,
                u64e(bytes, p + 16, little)?,
                bytes[p + 4],
                bytes[p + 5],
                u16e(bytes, p + 6, little)?,
            )
        } else {
            (
                u32e(bytes, p, little)?,
                u32e(bytes, p + 4, little)? as u64,
                u32e(bytes, p + 8, little)? as u64,
                bytes[p + 12],
                bytes[p + 13],
                u16e(bytes, p + 14, little)?,
            )
        };
        let nm = string_name(bytes, Some((stroff, strsz)), name)?;
        out.push(Symbol {
            table_index: 0,
            entry_index: e as usize,
            name: nm,
            name_offset: hex(name as u64),
            location: checked_range(bytes, symoff + e * syment, syment)?,
            value: hex(value),
            value_meaning: symbol_value_meaning(3, shndx, info, value),
            size: hex(size),
            binding: symbol_binding(info >> 4),
            kind: symbol_type(info & 15),
            visibility: symbol_visibility(other & 3),
            section_index: shndx.to_string(),
            reported_section_index: shndx.to_string(),
            version: None,
            version_index: None,
            version_location: None,
            version_state: "unknown",
            version_hidden: false,
        });
    }
    attach_dynamic_versions(
        bytes,
        &loads,
        strtab,
        strsz,
        versym,
        verdef,
        verdef_num,
        verneed,
        verneed_num,
        little,
        &mut out,
    )?;
    Ok(out)
}

fn mapped_dynamic_offset(loads: &[(u64, u64, u64)], address: u64, size: u64) -> Option<u64> {
    loads
        .iter()
        .find_map(|(virtual_address, segment_size, file_offset)| {
            let end = virtual_address.checked_add(*segment_size)?;
            let requested_end = address.checked_add(size)?;
            if address >= *virtual_address && requested_end <= end {
                Some(file_offset + (address - virtual_address))
            } else {
                None
            }
        })
}

fn dynamic_gnu_hash(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Option<DynamicGnuHash>, Error> {
    let mut loads = Vec::new();
    let mut dynamic = None;

    for index in 0..phnum.min(16_384) {
        let Some(position) = phoff
            .checked_add(index.saturating_mul(phentsize))
            .and_then(|value| usize::try_from(value).ok())
        else {
            continue;
        };
        let kind = match u32e(bytes, position, little) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if bits == 64 {
            let Ok(file_offset) = u64e(bytes, position + 8, little) else {
                continue;
            };
            let Ok(virtual_address) = u64e(bytes, position + 16, little) else {
                continue;
            };
            let Ok(file_size) = u64e(bytes, position + 32, little) else {
                continue;
            };
            if kind == 1 {
                loads.push((virtual_address, file_size, file_offset));
            } else if kind == 2 {
                dynamic = Some((file_offset, file_size));
            }
        } else {
            let Ok(file_offset) = u32e(bytes, position + 4, little) else {
                continue;
            };
            let Ok(virtual_address) = u32e(bytes, position + 8, little) else {
                continue;
            };
            let Ok(file_size) = u32e(bytes, position + 16, little) else {
                continue;
            };
            if kind == 1 {
                loads.push((virtual_address as u64, file_size as u64, file_offset as u64));
            } else if kind == 2 {
                dynamic = Some((file_offset as u64, file_size as u64));
            }
        }
    }

    let Some((dynamic_offset, dynamic_size)) = dynamic else {
        return Ok(None);
    };
    let entry_width = if bits == 64 { 16 } else { 8 };
    let mut hash_address = None;
    for entry in 0..(dynamic_size / entry_width).min(16_384) {
        let Some(position) = dynamic_offset
            .checked_add(entry.saturating_mul(entry_width))
            .and_then(|value| usize::try_from(value).ok())
        else {
            break;
        };
        let tag = if bits == 64 {
            u64e(bytes, position, little)?
        } else {
            u32e(bytes, position, little)? as u64
        };
        let value = if bits == 64 {
            u64e(bytes, position + 8, little)?
        } else {
            u32e(bytes, position + 4, little)? as u64
        };
        if tag == 0 {
            break;
        }
        if tag == 0x6ffffef5 {
            hash_address = Some(value);
            break;
        }
    }

    let Some(hash_address) = hash_address else {
        return Ok(None);
    };
    let Some(hash_offset) = mapped_dynamic_offset(&loads, hash_address, 16) else {
        return Ok(Some(DynamicGnuHash {
            location: None,
            bucket_count: None,
            symbol_offset: None,
            bloom_word_count: None,
            bloom_shift: None,
            bloom_location: None,
            bucket_location: None,
            chain_location: None,
            symbol_count: None,
            malformed: true,
            unknown_reason: Some("DT_GNU_HASH is outside PT_LOAD"),
        }));
    };

    let word_size = if bits == 64 { 8u64 } else { 4 };
    let header = hash_offset as usize;
    let Some(location) = checked_range(bytes, hash_offset, 16).ok() else {
        return Ok(Some(DynamicGnuHash {
            location: None,
            bucket_count: None,
            symbol_offset: None,
            bloom_word_count: None,
            bloom_shift: None,
            bloom_location: None,
            bucket_location: None,
            chain_location: None,
            symbol_count: None,
            malformed: true,
            unknown_reason: Some("GNU hash header is truncated"),
        }));
    };
    let buckets = u32e(bytes, header, little)?;
    let symbol_offset = u32e(bytes, header + 4, little)?;
    let bloom_words = u32e(bytes, header + 8, little)?;
    let bloom_shift = u32e(bytes, header + 12, little)?;
    let bloom_bytes = u64::from(bloom_words).checked_mul(word_size);
    let bucket_bytes = u64::from(buckets).checked_mul(4);
    let Some(bloom_bytes) = bloom_bytes else {
        return Ok(Some(DynamicGnuHash {
            location: Some(location),
            bucket_count: Some(buckets),
            symbol_offset: Some(symbol_offset),
            bloom_word_count: Some(bloom_words),
            bloom_shift: Some(bloom_shift),
            bloom_location: None,
            bucket_location: None,
            chain_location: None,
            symbol_count: None,
            malformed: true,
            unknown_reason: Some("GNU hash bloom size overflows"),
        }));
    };
    let Some(bucket_bytes) = bucket_bytes else {
        return Ok(Some(DynamicGnuHash {
            location: Some(location),
            bucket_count: Some(buckets),
            symbol_offset: Some(symbol_offset),
            bloom_word_count: Some(bloom_words),
            bloom_shift: Some(bloom_shift),
            bloom_location: None,
            bucket_location: None,
            chain_location: None,
            symbol_count: None,
            malformed: true,
            unknown_reason: Some("GNU hash bucket size overflows"),
        }));
    };
    let bloom_offset = hash_offset + 16;
    let Some(bucket_offset) = bloom_offset.checked_add(bloom_bytes) else {
        return Ok(Some(DynamicGnuHash {
            location: Some(location),
            bucket_count: Some(buckets),
            symbol_offset: Some(symbol_offset),
            bloom_word_count: Some(bloom_words),
            bloom_shift: Some(bloom_shift),
            bloom_location: None,
            bucket_location: None,
            chain_location: None,
            symbol_count: None,
            malformed: true,
            unknown_reason: Some("GNU hash table offsets overflow"),
        }));
    };
    let Some(chain_offset) = bucket_offset.checked_add(bucket_bytes) else {
        return Ok(Some(DynamicGnuHash {
            location: Some(location),
            bucket_count: Some(buckets),
            symbol_offset: Some(symbol_offset),
            bloom_word_count: Some(bloom_words),
            bloom_shift: Some(bloom_shift),
            bloom_location: None,
            bucket_location: None,
            chain_location: None,
            symbol_count: None,
            malformed: true,
            unknown_reason: Some("GNU hash table offsets overflow"),
        }));
    };
    let table_end_address = hash_address
        .checked_add(16)
        .and_then(|value| value.checked_add(bloom_bytes))
        .and_then(|value| value.checked_add(bucket_bytes));
    let table_in_load = table_end_address.is_some_and(|end| {
        loads
            .iter()
            .any(|(base, size, _)| hash_address >= *base && end <= base.saturating_add(*size))
    });
    if !table_in_load
        || checked_dynamic_range(bytes, bloom_offset, bloom_bytes).is_none()
        || checked_dynamic_range(bytes, bucket_offset, bucket_bytes).is_none()
    {
        return Ok(Some(DynamicGnuHash {
            location: Some(location),
            bucket_count: Some(buckets),
            symbol_offset: Some(symbol_offset),
            bloom_word_count: Some(bloom_words),
            bloom_shift: Some(bloom_shift),
            bloom_location: None,
            bucket_location: None,
            chain_location: None,
            symbol_count: None,
            malformed: true,
            unknown_reason: Some("GNU hash bloom or bucket table is truncated"),
        }));
    }

    let mut symbol_count = None;
    let mut first_chain = u64::MAX;
    let mut last_chain = chain_offset;
    let mut malformed = false;
    for bucket in 0..buckets.min(16_384) {
        let bucket_position = bucket_offset + u64::from(bucket) * 4;
        let bucket_value = u32e(bytes, bucket_position as usize, little)?;
        if bucket_value < symbol_offset {
            continue;
        }
        let chain = chain_offset.saturating_add(
            u64::from(bucket_value.saturating_sub(symbol_offset)).saturating_mul(4),
        );
        let mut terminated = false;
        for step in 0..16_384u64 {
            let Some(position) = chain.checked_add(step.saturating_mul(4)) else {
                malformed = true;
                break;
            };
            if checked_dynamic_range(bytes, position, 4).is_none() {
                malformed = true;
                break;
            }
            first_chain = first_chain.min(position);
            last_chain = last_chain.max(position + 4);
            let value = u32e(bytes, position as usize, little)?;
            symbol_count = Some(
                symbol_count
                    .unwrap_or(0)
                    .max(u64::from(bucket_value) + step + 1),
            );
            if value & 1 != 0 {
                terminated = true;
                break;
            }
        }
        if !terminated {
            malformed = true;
        }
    }

    Ok(Some(DynamicGnuHash {
        location: Some(location),
        bucket_count: Some(buckets),
        symbol_offset: Some(symbol_offset),
        bloom_word_count: Some(bloom_words),
        bloom_shift: Some(bloom_shift),
        bloom_location: checked_range(bytes, bloom_offset, bloom_bytes).ok(),
        bucket_location: checked_range(bytes, bucket_offset, bucket_bytes).ok(),
        chain_location: if first_chain == u64::MAX {
            None
        } else {
            checked_range(bytes, first_chain, last_chain.saturating_sub(first_chain)).ok()
        },
        symbol_count,
        malformed,
        unknown_reason: if malformed {
            Some("GNU hash chain is truncated or unterminated")
        } else {
            None
        },
    }))
}

fn dynamic_version_name(
    bytes: &[u8],
    loads: &[(u64, u64, u64)],
    strtab: u64,
    strsz: u64,
    offset: u32,
) -> Result<Option<String>, Error> {
    let Some(file_offset) = mapped_dynamic_offset(loads, strtab, strsz) else {
        return Ok(None);
    };
    if u64::from(offset) >= strsz {
        return Ok(None);
    }
    Ok(Some(
        string_name(bytes, Some((file_offset, strsz)), offset)?.display,
    ))
}

fn dynamic_version_names(
    bytes: &[u8],
    loads: &[(u64, u64, u64)],
    strtab: u64,
    strsz: u64,
    verdef: Option<u64>,
    verdef_num: Option<u64>,
    verneed: Option<u64>,
    verneed_num: Option<u64>,
    little: bool,
) -> Result<std::collections::BTreeMap<u16, String>, Error> {
    let mut names = std::collections::BTreeMap::new();

    if let (Some(address), Some(count)) = (verdef, verdef_num) {
        if let Some(file_offset) = mapped_dynamic_offset(loads, address, count.saturating_mul(20)) {
            let mut current = file_offset;
            for _ in 0..count.min(16_384) {
                let Some(header) = checked_dynamic_range(bytes, current, 20) else {
                    break;
                };
                let index = u16e(bytes, header + 4, little)?;
                let auxiliary = u32e(bytes, header + 12, little)? as u64;
                let Some(auxiliary) = checked_dynamic_range(bytes, current + auxiliary, 8) else {
                    break;
                };
                let name_offset = u32e(bytes, auxiliary, little)?;
                if let Some(name) = dynamic_version_name(bytes, loads, strtab, strsz, name_offset)?
                {
                    names.insert(index, name);
                }
                let next = u32e(bytes, header + 16, little)? as u64;
                if next == 0 {
                    break;
                }
                let Some(next_address) = current.checked_add(next) else {
                    break;
                };
                if next_address <= current {
                    break;
                }
                current = next_address;
            }
        }
    }

    if let (Some(address), Some(count)) = (verneed, verneed_num) {
        if let Some(file_offset) = mapped_dynamic_offset(loads, address, count.saturating_mul(16)) {
            let mut current = file_offset;
            for _ in 0..count.min(16_384) {
                let Some(header) = checked_dynamic_range(bytes, current, 16) else {
                    break;
                };
                let mut auxiliary = u32e(bytes, header + 8, little)? as u64;
                let auxiliary_count = u16e(bytes, header + 2, little)?;
                for _ in 0..u64::from(auxiliary_count).min(16_384) {
                    let Some(auxiliary_offset) =
                        checked_dynamic_range(bytes, current + auxiliary, 16)
                    else {
                        break;
                    };
                    let index = u16e(bytes, auxiliary_offset + 6, little)?;
                    let name_offset = u32e(bytes, auxiliary_offset + 8, little)?;
                    if let Some(name) =
                        dynamic_version_name(bytes, loads, strtab, strsz, name_offset)?
                    {
                        names.insert(index, name);
                    }
                    let next = u32e(bytes, auxiliary_offset + 12, little)? as u64;
                    if next == 0 {
                        break;
                    }
                    let Some(next_auxiliary) = auxiliary.checked_add(next) else {
                        break;
                    };
                    if next_auxiliary <= auxiliary {
                        break;
                    }
                    auxiliary = next_auxiliary;
                }
                let next = u32e(bytes, header + 12, little)? as u64;
                if next == 0 {
                    break;
                }
                let Some(next_address) = current.checked_add(next) else {
                    break;
                };
                if next_address <= current {
                    break;
                }
                current = next_address;
            }
        }
    }

    Ok(names)
}

fn checked_dynamic_range(bytes: &[u8], offset: u64, size: u64) -> Option<usize> {
    let end = offset.checked_add(size)?;
    if end > bytes.len() as u64 {
        return None;
    }
    Some(offset as usize)
}

fn attach_dynamic_versions(
    bytes: &[u8],
    loads: &[(u64, u64, u64)],
    strtab: u64,
    strsz: u64,
    versym: Option<u64>,
    verdef: Option<u64>,
    verdef_num: Option<u64>,
    verneed: Option<u64>,
    verneed_num: Option<u64>,
    little: bool,
    symbols: &mut [Symbol],
) -> Result<(), Error> {
    let Some(versym) = versym else {
        return Ok(());
    };
    let names = dynamic_version_names(
        bytes,
        loads,
        strtab,
        strsz,
        verdef,
        verdef_num,
        verneed,
        verneed_num,
        little,
    )?;
    for symbol in symbols {
        let Some(address) = versym.checked_add((symbol.entry_index as u64).saturating_mul(2))
        else {
            symbol.version_state = "malformed";
            continue;
        };
        let Some(offset) = mapped_dynamic_offset(loads, address, 2) else {
            symbol.version_state = "malformed";
            continue;
        };
        let Some(location) = checked_range(bytes, offset, 2).ok() else {
            symbol.version_state = "malformed";
            continue;
        };
        let index = u16e(bytes, offset as usize, little)?;
        let version_index = index & 0x7fff;

        symbol.version_index = Some(index);
        symbol.version_location = Some(location);
        symbol.version_hidden = index & 0x8000 != 0;
        symbol.version = names.get(&version_index).cloned();
        symbol.version_state = if version_index == 0 {
            "unversioned"
        } else if symbol.version.is_some() {
            "resolved"
        } else {
            "unresolved"
        };
    }
    Ok(())
}

fn section_relr(
    bytes: &[u8],
    sections: &[(u32, u64, u64, u64, u64, usize, usize, u64, u64, u32)],
    little: bool,
    bits: u8,
) -> Result<Vec<PackedRelocation>, Error> {
    let width = if bits == 64 { 8 } else { 4 };
    let mut packed = Vec::new();
    for (section_index, section) in sections.iter().enumerate() {
        if section.0 != 19 {
            continue;
        }
        if section.8 != 0 && section.8 != width {
            return Err(Error::Format("ELF RELR section has an invalid entry width"));
        }
        if section.4 % width != 0 {
            return Err(Error::Format("ELF RELR section size is not entry-aligned"));
        }
        packed.push(decode_relr(
            bytes,
            section.3,
            section.4,
            section_index,
            little,
            bits,
        )?);
    }
    Ok(packed)
}

fn decode_relr(
    bytes: &[u8],
    offset: u64,
    size: u64,
    section_index: usize,
    little: bool,
    bits: u8,
) -> Result<PackedRelocation, Error> {
    let width = if bits == 64 { 8 } else { 4 };
    let word_bits = width * 8;
    let location = checked_range(bytes, offset, size)?;
    let end = offset
        .checked_add(size)
        .ok_or(Error::Format("ELF RELR range overflowed"))?;
    checked_range(bytes, offset, size)?;
    let mut entries = Vec::new();
    let mut next = 0u64;
    let mut decoded_index = 0usize;
    let mut at = offset;
    while at < end {
        let value = if bits == 64 {
            u64e(bytes, at as usize, little)?
        } else {
            u32e(bytes, at as usize, little)? as u64
        };
        if value & 1 == 0 {
            next = value;
            entries.push(PackedEntry {
                decoded_index,
                reported_offset: hex(value),
            });
            decoded_index += 1;
            next = next
                .checked_add(width as u64)
                .ok_or(Error::Format("ELF RELR relocation offset overflowed"))?;
        } else {
            if next == 0 {
                return Err(Error::Format("ELF RELR bitmap precedes its base offset"));
            }
            for bit in 1..word_bits {
                if value & (1u64 << bit) != 0 {
                    let relocation = next
                        .checked_add((bit as u64 - 1) * width as u64)
                        .ok_or(Error::Format("ELF RELR bitmap offset overflowed"))?;
                    entries.push(PackedEntry {
                        decoded_index,
                        reported_offset: hex(relocation),
                    });
                    decoded_index += 1;
                }
            }
            next = next
                .checked_add((word_bits as u64 - 1) * width as u64)
                .ok_or(Error::Format("ELF RELR bitmap stride overflowed"))?;
        }
        at = at
            .checked_add(width as u64)
            .ok_or(Error::Format("ELF RELR entry offset overflowed"))?;
        if decoded_index > 1_000_000 {
            return Err(Error::Format(
                "ELF RELR expansion exceeds the resource bound",
            ));
        }
    }
    Ok(PackedRelocation {
        section_index,
        location,
        encoded_bytes_base64: base64(&bytes[offset as usize..(offset + size) as usize]),
        entries,
        offset_meaning: "linked-virtual-address",
        evidence_kind: "observed",
        entry_source_locations: None,
        addends: None,
    })
}

fn dynamic_relr(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Vec<PackedRelocation>, Error> {
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..phnum {
        let p = (phoff + index * phentsize) as usize;
        let kind = u32e(bytes, p, little)?;
        let (file_offset, virtual_address, file_size) = if bits == 64 {
            (
                u64e(bytes, p + 8, little)?,
                u64e(bytes, p + 16, little)?,
                u64e(bytes, p + 32, little)?,
            )
        } else {
            (
                u32e(bytes, p + 4, little)? as u64,
                u32e(bytes, p + 8, little)? as u64,
                u32e(bytes, p + 16, little)? as u64,
            )
        };
        if kind == 1 {
            loads.push((virtual_address, file_size, file_offset));
        } else if kind == 2 {
            let size = if bits == 64 {
                u64e(bytes, p + 40, little)?
            } else {
                u32e(bytes, p + 20, little)? as u64
            };
            dynamic = Some((file_offset, size));
        }
    }
    let Some((offset, size)) = dynamic else {
        return Ok(Vec::new());
    };
    let entry_width = if bits == 64 { 16 } else { 8 };
    let mut table = None;
    let mut table_size = None;
    let mut table_entry_size = if bits == 64 { 8 } else { 4 };
    for address in (offset..offset.saturating_add(size)).step_by(entry_width) {
        let p = address as usize;
        let tag = if bits == 64 {
            u64e(bytes, p, little)?
        } else {
            u32e(bytes, p, little)? as u64
        };
        let value = if bits == 64 {
            u64e(bytes, p + 8, little)?
        } else {
            u32e(bytes, p + 4, little)? as u64
        };
        if tag == 0 {
            break;
        }
        match tag {
            35 => table_size = Some(value),
            36 => table = Some(value),
            37 => table_entry_size = value,
            _ => {}
        }
    }
    let (Some(table), Some(table_size)) = (table, table_size) else {
        return Ok(Vec::new());
    };
    let expected_width = if bits == 64 { 8 } else { 4 };
    if table_entry_size != expected_width || table_size % expected_width != 0 {
        return Err(Error::Format("ELF DT_RELR has an invalid entry width"));
    }
    let Some(file_offset) = mapped_dynamic_offset(&loads, table, table_size) else {
        return Err(Error::Format("ELF DT_RELR is outside PT_LOAD file backing"));
    };
    Ok(vec![decode_relr(
        bytes,
        file_offset,
        table_size,
        usize::MAX,
        little,
        bits,
    )?])
}

fn dynamic_relocations(
    bytes: &[u8],
    little: bool,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    bits: u8,
) -> Result<Vec<Relocation>, Error> {
    let mut loads = Vec::new();
    let mut dynamic = None;
    for i in 0..phnum {
        let p = (phoff + i * phentsize) as usize;
        let kind = u32e(bytes, p, little)?;
        let (off, va, size) = if bits == 64 {
            (
                u64e(bytes, p + 8, little)?,
                u64e(bytes, p + 16, little)?,
                u64e(bytes, p + 32, little)?,
            )
        } else {
            (
                u32e(bytes, p + 4, little)? as u64,
                u32e(bytes, p + 8, little)? as u64,
                u32e(bytes, p + 16, little)? as u64,
            )
        };
        if kind == 1 {
            loads.push((va, size, off));
        }
        if kind == 2 {
            dynamic = Some((off, size));
        }
    }
    let Some((off, size)) = dynamic else {
        return Ok(Vec::new());
    };
    let width = if bits == 64 { 16 } else { 8 };
    let mut rel = None;
    let mut relsz = 0;
    let mut relent = 0;
    let mut rela = None;
    let mut relasz = 0;
    let mut relaent = 0;
    let mut jmprel = None;
    let mut pltrelsz = 0;
    let mut pltrel = 0;
    for at in (off..off.saturating_add(size)).step_by(width) {
        let p = at as usize;
        let tag = if bits == 64 {
            u64e(bytes, p, little)?
        } else {
            u32e(bytes, p, little)? as u64
        };
        let val = if bits == 64 {
            u64e(bytes, p + 8, little)?
        } else {
            u32e(bytes, p + 4, little)? as u64
        };
        if tag == 0 {
            break;
        }
        match tag {
            17 => rel = Some(val),
            18 => relsz = val,
            19 => relent = val,
            7 => rela = Some(val),
            8 => relasz = val,
            9 => relaent = val,
            23 => jmprel = Some(val),
            2 => pltrelsz = val,
            20 => pltrel = val,
            _ => {}
        }
    }
    let mut out = Vec::new();
    let mut decode = |base: u64, total: u64, entry: u64, addend: bool| -> Result<(), Error> {
        if entry == 0 || total % entry != 0 {
            return Ok(());
        }
        let Some((sv, _ss, so)) = loads
            .iter()
            .find(|(v, s, _)| base >= *v && base.saturating_add(total) <= v.saturating_add(*s))
        else {
            return Ok(());
        };
        let file = *so + base - *sv;
        for e in 0..(total / entry).min(65_536) {
            let p = (file + e * entry) as usize;
            let (off, info, add) = if bits == 64 {
                (
                    u64e(bytes, p, little)?,
                    u64e(bytes, p + 8, little)?,
                    if addend {
                        Some(u64e(bytes, p + 16, little)? as i64)
                    } else {
                        None
                    },
                )
            } else {
                (
                    u32e(bytes, p, little)? as u64,
                    u32e(bytes, p + 4, little)? as u64,
                    if addend {
                        Some(u32e(bytes, p + 8, little)? as i32 as i64)
                    } else {
                        None
                    },
                )
            };
            let symbol_index = if bits == 64 {
                (info >> 32) as usize
            } else {
                (info >> 8) as usize
            };
            out.push(Relocation {
                section_index: usize::MAX,
                entry_index: e as usize,
                reported_offset: hex(off),
                target: RelocationTarget::LinkedVirtualAddress { address: hex(off) },
                location: checked_range(bytes, file + e * entry, entry)?,
                kind: if bits == 64 {
                    (info & 0xffff_ffff) as usize
                } else {
                    (info & 0xff) as usize
                },
                symbol_table_index: 0,
                symbol_index,
                symbol_reference_meaning: relocation_symbol_reference_meaning(symbol_index),
                addend: add.map(|x| x.to_string()),
                symbol: None,
                symbol_version: None,
                symbol_version_hidden: false,
                symbol_resolution: "unresolved",
            });
        }
        Ok(())
    };
    if let Some(base) = rel {
        decode(
            base,
            relsz,
            if relent == 0 {
                if bits == 64 { 16 } else { 8 }
            } else {
                relent
            },
            false,
        )?;
    }
    if let Some(base) = rela {
        decode(
            base,
            relasz,
            if relaent == 0 {
                if bits == 64 { 24 } else { 12 }
            } else {
                relaent
            },
            true,
        )?;
    }
    if let Some(base) = jmprel {
        decode(
            base,
            pltrelsz,
            if pltrel == 7 {
                if relaent == 0 { 24 } else { relaent }
            } else {
                if relent == 0 { 16 } else { relent }
            },
            pltrel == 7,
        )?;
    }
    Ok(out)
}

fn relocation_symbol_reference_meaning(symbol_index: usize) -> &'static str {
    if symbol_index == 0 {
        "zero-symbol-value"
    } else {
        "symbol-table-entry"
    }
}

fn attach_relocation_symbols(relocations: &mut [Relocation], symbols: &[Symbol]) {
    for relocation in relocations.iter_mut() {
        if relocation.symbol_reference_meaning == "zero-symbol-value" {
            relocation.symbol_resolution = "zero-symbol-value";
            continue;
        }
        let Some(symbol) = symbols.iter().find(|symbol| {
            symbol.table_index == relocation.symbol_table_index
                && symbol.entry_index == relocation.symbol_index
        }) else {
            relocation.symbol_resolution = "missing-symbol";
            continue;
        };
        relocation.symbol = Some(symbol.name.clone());
        relocation.symbol_version = symbol.version.clone();
        relocation.symbol_version_hidden = symbol.version_hidden;
        relocation.symbol_resolution =
            symbol_resolution_label(symbol.version.as_deref(), symbol.version_state);
    }
}

fn symbol_resolution_label(version: Option<&str>, version_state: &str) -> &'static str {
    if version.is_some() {
        "resolved-versioned-symbol"
    } else if version_state == "unknown" {
        "resolved-symbol-version-unknown"
    } else {
        "resolved-symbol"
    }
}

fn dynamic_linkage_maps(relocations: &[Relocation]) -> (Vec<LinkedName>, Vec<LinkedName>) {
    let mut got = Vec::new();
    let mut plt = Vec::new();

    for relocation in relocations {
        if relocation.section_index != usize::MAX {
            continue;
        }
        let Some(symbol) = relocation.symbol.as_ref() else {
            continue;
        };
        let RelocationTarget::LinkedVirtualAddress { address } = &relocation.target else {
            continue;
        };
        let destination = if relocation.kind == 7 {
            &mut plt
        } else {
            &mut got
        };
        if destination.iter().any(|entry: &LinkedName| {
            entry.display_name == symbol.display && entry.address == *address
        }) {
            continue;
        }
        destination.push(LinkedName {
            display_name: symbol.display.clone(),
            address: address.clone(),
        });
    }

    (got, plt)
}

fn read_elf32(bytes: &[u8], little: bool) -> Result<Layout, Error> {
    if bytes.len() < 52 {
        return Err(Error::Format("ELF32 header is truncated"));
    }
    let machine = u16e(bytes, 18, little)?;
    let et = u16e(bytes, 16, little)?;
    let image_type = match et {
        1 => "ET_REL",
        2 => "ET_EXEC",
        3 => "ET_DYN",
        _ => {
            return Err(Error::Unsupported(
                "ELF32 type is outside the EXEC/DYN/REL layout profile",
            ));
        }
    }
    .to_owned();
    let entry = u32e(bytes, 24, little)? as u64;
    let phoff = u32e(bytes, 28, little)? as u64;
    let shoff = u32e(bytes, 32, little)? as u64;
    let phentsize = u16e(bytes, 42, little)? as u64;
    let phnum = u16e(bytes, 44, little)? as u64;
    let shentsize = u16e(bytes, 46, little)? as u64;
    let shnum = u16e(bytes, 48, little)? as u64;
    let shstr = u16e(bytes, 50, little)? as u64;
    let mut extended_numbering = None;
    let mut shnum = shnum;
    let mut shstr = shstr;
    let mut phnum = phnum;
    if (0xff00..0xffff).contains(&shstr) {
        return Err(Error::Format(
            "ELF32 section-name index is reserved and cannot directly reference a section",
        ));
    }
    if (shnum == 0 && shoff != 0) || shstr == 0xffff || phnum == 0xffff {
        if shentsize < 40 {
            return Err(Error::Format(
                "invalid ELF32 section-zero width for extended numbering",
            ));
        }
        let section_zero_location = checked_range(bytes, shoff, 40)?;
        if shstr == 0xffff && shoff == 0 {
            return Err(Error::Format(
                "ELF32 extended section-name index requires a declared section-zero header",
            ));
        }
        let zero = shoff as usize;
        let zero_size = u32e(bytes, zero + 20, little)? as u64;
        let zero_link = u32e(bytes, zero + 24, little)? as u64;
        let zero_info = u32e(bytes, zero + 28, little)? as u64;
        if shstr == 0xffff && shnum == 0 && zero_size == 0 {
            return Err(Error::Format(
                "ELF32 extended section-name index requires a declared section-zero header",
            ));
        }
        let resolved_shnum = if shnum == 0 { Some(zero_size) } else { None };
        let resolved_phnum = if phnum == 0xffff {
            Some(zero_info)
        } else {
            None
        };
        let resolved_shstr = if shstr == 0xffff {
            Some(zero_link)
        } else {
            None
        };
        if shstr == 0xffff && zero_link != 0 && zero_link < 0xff00 {
            return Err(Error::Format(
                "ELF32 SHN_XINDEX resolves to an ordinary section-name index; the escape requires an index at least SHN_LORESERVE",
            ));
        }
        if let Some(value) = resolved_shnum {
            shnum = value;
        }
        if let Some(value) = resolved_phnum {
            phnum = value;
        }
        if let Some(value) = resolved_shstr {
            shstr = value;
        }
        extended_numbering = Some(ExtendedNumbering {
            section_count: resolved_shnum,
            program_count: resolved_phnum,
            section_name_index: resolved_shstr,
            section_zero_location,
        });
    }
    if shnum > 0 && shentsize < 40 {
        return Err(Error::Format("invalid ELF32 section width"));
    }
    let mut raw = Vec::new();
    for i in 0..shnum {
        let p = (shoff + i * shentsize) as usize;
        let kind = u32e(bytes, p + 4, little)?;
        let addr = u32e(bytes, p + 12, little)? as u64;
        let off = u32e(bytes, p + 16, little)? as u64;
        let size = u32e(bytes, p + 20, little)? as u64;
        let flags = u32e(bytes, p + 8, little)? as u64;
        let link = u32e(bytes, p + 24, little)? as usize;
        let info = u32e(bytes, p + 28, little)? as usize;
        let align = u32e(bytes, p + 32, little)? as u64;
        let entsize = u32e(bytes, p + 36, little)? as u64;
        let name = u32e(bytes, p, little)?;
        if kind != 0 && kind != 8 {
            checked_range(bytes, off, size)?;
        }
        raw.push((
            kind, flags, addr, off, size, link, info, align, entsize, name,
        ));
    }
    let names = if shstr == 0 {
        None
    } else {
        let s = raw.get(shstr as usize).ok_or(Error::Format(
            "ELF32 section-name index is outside the section table",
        ))?;
        if s.0 != 3 {
            return Err(Error::Format("ELF32 section-name table is not SHT_STRTAB"));
        }
        checked_range(bytes, s.3, s.4)?;
        Some((s.3, s.4))
    };
    let mut sections = Vec::new();
    for (i, s) in raw.iter().enumerate() {
        sections.push(Section {
            index: i,
            name: string_name(bytes, names, s.9)?,
            name_offset: hex(s.9 as u64),
            kind: section_kind(s.0),
            header_location: checked_range(bytes, shoff + i as u64 * shentsize, shentsize)?,
            address: hex(s.2),
            offset: hex(s.3),
            size: hex(s.4),
            alignment: hex(s.7),
            flags: hex(s.1),
            link: s.5,
            info: s.6,
            entry_size: hex(s.8),
            file_backing: if s.0 == 0 || s.0 == 8 { "none" } else { "file" },
            compression: compressed_section(bytes, s.1, s.3, s.4, little, 32)?,
        });
    }
    let mut segments = Vec::new();
    let mut execstack = false;
    let mut stack_policy = None;
    let mut relro_policy = None;
    let mut tls_segments = Vec::new();
    let mut eh_frame_segments = Vec::new();
    for i in 0..phnum {
        let p = (phoff + i * phentsize) as usize;
        let kind = u32e(bytes, p, little)?;
        let off = u32e(bytes, p + 4, little)? as u64;
        let va = u32e(bytes, p + 8, little)? as u64;
        let pa = u32e(bytes, p + 12, little)? as u64;
        let fs = u32e(bytes, p + 16, little)? as u64;
        let ms = u32e(bytes, p + 20, little)? as u64;
        let flags = u32e(bytes, p + 24, little)?;
        let al = u32e(bytes, p + 28, little)? as u64;
        if kind == 1 && ms < fs {
            return Err(Error::Format(
                "ELF load segment memory size is smaller than its file size.",
            ));
        }
        if kind != 0 && fs > 0 {
            checked_range(bytes, off, fs)?;
        }
        if kind == 0x6474e551 {
            execstack = flags & 1 != 0;
            stack_policy = Some(stack_policy_metadata(
                i as usize,
                flags,
                checked_range(bytes, phoff + i * phentsize, phentsize)?,
                stack_policy.is_some(),
            ));
        }
        if kind == 0x6474e552 {
            relro_policy = Some(relro_segment_metadata(
                i as usize,
                off,
                fs,
                va,
                ms,
                flags,
                checked_range(bytes, phoff + i * phentsize, phentsize)?,
                relro_policy.is_some(),
                checked_range(bytes, off, fs).ok(),
            ));
        }
        if kind == 7 {
            tls_segments.push(tls_segment_metadata(
                i as usize,
                off,
                fs,
                va,
                ms,
                al,
                flags,
                checked_range(bytes, phoff + i * phentsize, phentsize)?,
                checked_range(bytes, off, fs).ok(),
            ));
        }
        if kind == 0x6474e550 {
            eh_frame_segments.push(eh_frame_segment_metadata(
                i as usize,
                off,
                fs,
                va,
                ms,
                al,
                flags,
                checked_range(bytes, off, fs).ok(),
            ));
        }
        segments.push(Segment {
            index: i as usize,
            kind: segment_kind(kind),
            header_location: checked_range(bytes, phoff + i * phentsize, phentsize)?,
            offset: hex(off),
            file_size: hex(fs),
            memory_size: hex(ms),
            virtual_address: hex(va),
            physical_address: hex(pa),
            alignment: hex(al),
            flags: hex(flags as u64),
            file_backing: if kind != 0 && fs > 0 { "file" } else { "none" },
            permissions: if kind == 0 {
                None
            } else {
                Some(Permissions {
                    read: flags & 4 != 0,
                    write: flags & 2 != 0,
                    execute: flags & 1 != 0,
                })
            },
        });
    }
    let mut symbols = Vec::new();
    let mut relocations = Vec::new();
    for (table, s) in raw.iter().enumerate() {
        if s.0 == 2 || s.0 == 11 {
            validate_symbol_table_layout(
                s.8,
                s.4,
                16,
                "ELF32 symbol entry is smaller than the decoded Elf32_Sym structure.",
            )?;
            let strings = Some(validate_symbol_string_table(&raw, s.5)?);
            let count = (s.4 / s.8) as usize;
            let extended_indices = extended_symbol_indices(bytes, &raw, table, count, little)?;
            for e in 0..count {
                let p = (s.3 + e as u64 * s.8) as usize;
                let name = u32e(bytes, p, little)?;
                let value = u32e(bytes, p + 4, little)? as u64;
                let size = u32e(bytes, p + 8, little)? as u64;
                let info = bytes[p + 12];
                let other = bytes[p + 13];
                let shndx = u16e(bytes, p + 14, little)?;
                let reported_section_index = shndx.to_string();
                let resolved_section_index = if shndx == 0xffff {
                    extended_indices
                        .as_ref()
                        .and_then(|indices| indices.get(e))
                        .map(|index| index.to_string())
                        .unwrap_or_else(|| "SHN_XINDEX (unresolved)".into())
                } else {
                    reported_section_index.clone()
                };
                symbols.push(Symbol {
                    table_index: table,
                    entry_index: e as usize,
                    name: string_name(bytes, strings, name)?,
                    name_offset: hex(name as u64),
                    location: checked_range(bytes, s.3 + e as u64 * s.8, s.8)?,
                    value: hex(value),
                    value_meaning: symbol_value_meaning(et, shndx, info, value),
                    size: hex(size),
                    binding: symbol_binding(info >> 4),
                    kind: symbol_type(info & 15),
                    visibility: symbol_visibility(other & 3),
                    section_index: resolved_section_index,
                    reported_section_index,
                    version: None,
                    version_index: None,
                    version_location: None,
                    version_state: "unknown",
                    version_hidden: false,
                });
            }
        }
        if s.0 == 9 || s.0 == 4 {
            let width = if s.0 == 9 { 8 } else { 12 };
            if s.8 < width || s.4 % s.8 != 0 {
                return Err(Error::Format(
                    "ELF32 relocation section has an invalid entry width",
                ));
            }
            for e in 0..(s.4 / s.8) {
                let p = (s.3 + e * s.8) as usize;
                let off = u32e(bytes, p, little)? as u64;
                let info = u32e(bytes, p + 4, little)? as u64;
                let add = if width == 12 {
                    Some(u32e(bytes, p + 8, little)? as i32 as i64)
                } else {
                    None
                };
                validate_relocation_target_section(et, s.6, raw.len())?;
                validate_relocation_symbol_index(&raw, s.5, info >> 8)?;
                let target = if et == 1 {
                    if s.6 == 0 {
                        RelocationTarget::UnknownSection {
                            reported_section_index: 0,
                            offset: hex(off),
                            unknown_reason: "undefined-section-reference",
                        }
                    } else {
                        RelocationTarget::SectionOffset {
                            section_index: s.6,
                            offset: hex(off),
                        }
                    }
                } else {
                    RelocationTarget::LinkedVirtualAddress { address: hex(off) }
                };
                relocations.push(Relocation {
                    section_index: table,
                    entry_index: e as usize,
                    reported_offset: hex(off),
                    target,
                    location: checked_range(bytes, s.3 + e * s.8, s.8)?,
                    kind: (info & 0xff) as usize,
                    symbol_table_index: s.5,
                    symbol_index: (info >> 8) as usize,
                    symbol_reference_meaning: if info >> 8 == 0 {
                        "zero-symbol-value"
                    } else {
                        "symbol-table-entry"
                    },
                    addend: add.map(|x| x.to_string()),
                    symbol: None,
                    symbol_version: None,
                    symbol_version_hidden: false,
                    symbol_resolution: "unresolved",
                });
            }
        }
    }
    let mut packed_relative_relocations = section_relr(bytes, &raw, little, 32)?;
    packed_relative_relocations.extend(dynamic_relr(bytes, little, phoff, phnum, phentsize, 32)?);
    let machine_name = match machine {
        3 => "EM_386",
        40 => "EM_ARM",
        62 => "EM_X86_64",
        183 => "EM_AARCH64",
        _ => "EM_UNKNOWN",
    };
    attach_section_versions(bytes, &raw, little, &mut symbols)?;
    symbols.extend(dynamic_symbols(bytes, little, phoff, phnum, phentsize, 32)?);
    relocations.extend(dynamic_relocations(
        bytes, little, phoff, phnum, phentsize, 32,
    )?);
    attach_relocation_symbols(&mut relocations, &symbols);
    let stack_canary_indicator = has_stack_canary_symbols(&symbols);
    let (got, plt) = dynamic_linkage_maps(&relocations);
    let needed_libraries = dynamic_needed(bytes, little, phoff, phnum, phentsize, 32)?;
    let interpreters = interpreters(bytes, little, phoff, phnum, phentsize, 32)?;
    let mut notes = notes_from_segments(bytes, little, phoff, phnum, phentsize, 32)?;
    notes.extend(notes_from_sections(bytes, &raw, little, 32)?);
    let debug_links = debug_links_from_sections(bytes, &sections, little)?;
    let section_groups = section_groups(bytes, &raw, &symbols, little)?;
    let dynamic_flags = dynamic_flags(bytes, little, phoff, phnum, phentsize, 32)?;
    let relro = relro_mitigation(relro_policy.as_ref(), dynamic_flags.as_ref());
    let nx_indicator = nx_mitigation(stack_policy.as_ref());
    let dynamic_string_tags = dynamic_string_tags(bytes, little, phoff, phnum, phentsize, 32)?;
    let dynamic_gnu_hash = dynamic_gnu_hash(bytes, little, phoff, phnum, phentsize, 32)?;
    let symbol_version_tables = gnu_version_tables(bytes, &raw, little)?;
    Ok(Layout {
        format: "elf",
        architecture: Architecture {
            machine: machine_name.into(),
            bits: 32,
            byte_order: if little { "little" } else { "big" }.into(),
        },
        image_type: image_type.clone(),
        entry_point: EntryPoint {
            reported_value: hex(entry),
            meaning: if et == 1 {
                "not-applicable"
            } else if entry == 0 {
                "absent"
            } else {
                "linked-virtual-address"
            },
            execution_status: "unknown",
        },
        runtime_load_base: None,
        sections,
        segments,
        symbols,
        relocations,
        packed_relative_relocations,
        relocation_inventory_completeness: "unknown",
        linkage: Linkage {
            needed_libraries,
            interpreters,
            got,
            plt,
            convenience_maps_completeness: "unknown",
            runtime_library_paths: None,
        },
        mitigations: Mitigations {
            evidence_kind: "inferred",
            position_independent: et == 3,
            nx_indicator,
            executable_stack_indicator: execstack,
            stack_canary_indicator,
            relro,
        },
        notes,
        debug_links,
        section_groups,
        extended_numbering,
        stack_policy,
        relro_policy,
        tls_segments,
        eh_frame_segments,
        dynamic_flags,
        dynamic_string_tags,
        dynamic_gnu_hash,
        symbol_version_tables,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf32_header(big_endian: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 52];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 1;
        bytes[5] = if big_endian { 2 } else { 1 };
        bytes[6] = 1;
        let put16 = |at: usize, value: u16, out: &mut [u8]| {
            let encoded = if big_endian {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            out[at..at + 2].copy_from_slice(&encoded);
        };
        put16(16, 2, &mut bytes);
        put16(18, 3, &mut bytes);
        put16(40, 52, &mut bytes);
        put16(42, 32, &mut bytes);
        put16(46, 40, &mut bytes);
        bytes
    }

    #[test]
    fn parses_empty_elf32_little_endian() {
        let layout = read(&elf32_header(false)).unwrap();
        assert_eq!(layout.architecture.bits, 32);
        assert_eq!(layout.architecture.byte_order, "little");
        assert_eq!(layout.mitigations.nx_indicator, None);
    }

    #[test]
    fn detects_static_stack_canary_symbols_without_claiming_runtime_coverage() {
        let symbol = Symbol {
            table_index: 1,
            entry_index: 0,
            name: Name {
                display: "__stack_chk_fail".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            location: Range {
                offset: "0x0".into(),
                bytes: "0x18".into(),
            },
            value: "0x0".into(),
            value_meaning: "undefined",
            size: "0x0".into(),
            binding: "STB_GLOBAL".into(),
            kind: "STT_FUNC".into(),
            visibility: "STV_DEFAULT".into(),
            section_index: "0".into(),
            reported_section_index: "0".into(),
            version: None,
            version_index: None,
            version_location: None,
            version_state: "unknown",
            version_hidden: false,
        };

        assert!(has_stack_canary_symbols(&[symbol]));
        assert!(!has_stack_canary_symbols(&[]));
    }

    #[test]
    fn projects_valid_relro_segment_with_header_provenance() {
        let policy = relro_segment_metadata(
            3,
            0x400,
            0x80,
            0x8040_0000,
            0x100,
            4,
            Range {
                offset: "0x120".into(),
                bytes: "0x38".into(),
            },
            false,
            Some(Range {
                offset: "0x400".into(),
                bytes: "0x80".into(),
            }),
        );

        assert_eq!(policy.segment_index, 3);
        assert_eq!(policy.file_offset, "0x400");
        assert_eq!(policy.virtual_address, "0x80400000");
        assert_eq!(policy.policy, "present");
        assert!(!policy.malformed);
        assert_eq!(policy.header_location.offset, "0x120");
        assert_eq!(policy.source_location.as_ref().unwrap().offset, "0x400");
    }

    #[test]
    fn preserves_invalid_relro_extent_as_malformed() {
        let policy = relro_segment_metadata(
            1,
            0x200,
            0x180,
            0x1000,
            0x100,
            6,
            Range {
                offset: "0x40".into(),
                bytes: "0x20".into(),
            },
            false,
            Some(Range {
                offset: "0x200".into(),
                bytes: "0x180".into(),
            }),
        );

        assert!(policy.malformed);
        assert_eq!(policy.unknown_reason, Some("invalid-relro-range"));
        assert_eq!(policy.file_size, "0x180");
        assert_eq!(policy.memory_size, "0x100");
    }

    #[test]
    fn preserves_duplicate_relro_declaration_state() {
        let policy = relro_segment_metadata(
            2,
            0x300,
            0x40,
            0x5000,
            0x40,
            4,
            Range {
                offset: "0x90".into(),
                bytes: "0x38".into(),
            },
            true,
            Some(Range {
                offset: "0x300".into(),
                bytes: "0x40".into(),
            }),
        );

        assert!(policy.duplicate);
        assert!(policy.malformed);
        assert_eq!(
            policy.unknown_reason,
            Some("duplicate-PT_GNU_RELRO-declaration")
        );
        assert_eq!(policy.header_location.offset, "0x90");
    }

    #[test]
    fn preserves_missing_relro_source_bytes_as_unknown() {
        let policy = relro_segment_metadata(
            4,
            0,
            0,
            0x7000,
            0x40,
            4,
            Range {
                offset: "0x100".into(),
                bytes: "0x38".into(),
            },
            false,
            None,
        );

        assert!(policy.malformed);
        assert!(policy.source_location.is_none());
        assert_eq!(policy.unknown_reason, Some("relro-range-outside-snapshot"));
        assert_eq!(relro_mitigation(Some(&policy), None), None);
    }

    #[test]
    fn derives_partial_and_full_relro_mitigation_states() {
        let policy = relro_segment_metadata(
            0,
            0x100,
            0x40,
            0x4000,
            0x40,
            0,
            Range {
                offset: "0x20".into(),
                bytes: "0x38".into(),
            },
            false,
            Some(Range {
                offset: "0x100".into(),
                bytes: "0x40".into(),
            }),
        );
        let partial_flags = DynamicFlags {
            entries: Vec::new(),
            malformed: false,
            unknown_reason: None,
        };
        assert_eq!(
            relro_mitigation(Some(&policy), Some(&partial_flags)),
            Some("Partial".into())
        );

        let full_flags = DynamicFlags {
            entries: vec![DynamicFlagEntry {
                tag: "0x18".into(),
                value: "0x1".into(),
                named_bits: vec!["DT_BIND_NOW".into()],
                unknown_bits: Vec::new(),
                location: Range {
                    offset: "0x80".into(),
                    bytes: "0x10".into(),
                },
            }],
            malformed: false,
            unknown_reason: None,
        };
        assert_eq!(
            relro_mitigation(Some(&policy), Some(&full_flags)),
            Some("Full".into())
        );
        assert_eq!(relro_mitigation(None, Some(&full_flags)), None);
    }

    #[test]
    fn parses_empty_elf32_big_endian() {
        let layout = read(&elf32_header(true)).unwrap();
        assert_eq!(layout.architecture.bits, 32);
        assert_eq!(layout.architecture.byte_order, "big");
    }

    #[test]
    fn classifies_tls_symbol_values_as_offsets() {
        assert_eq!(symbol_value_meaning(3, 4, 6, 0), "tls-offset");
        assert_eq!(
            symbol_value_meaning(3, 4, 2, 0x10),
            "linked-virtual-address"
        );
        assert_eq!(symbol_value_meaning(1, 4, 6, 0), "tls-offset");
        assert_eq!(symbol_value_meaning(3, 0xfff2, 0, 0), "alignment");
        assert_eq!(
            symbol_value_meaning(3, 0xff00, 0, 0),
            "unknown-section-index"
        );
        assert_eq!(symbol_value_meaning(3, 4, 0, 0), "no-address");
    }

    #[test]
    fn projects_valid_tls_segment_metadata_for_elf32_and_elf64() {
        let location = Range {
            offset: "0x40".into(),
            bytes: "0x38".into(),
        };
        let elf64 = tls_segment_metadata(
            2,
            0x200,
            0x20,
            0x600000,
            0x40,
            0x20,
            4,
            location.clone(),
            Some(location.clone()),
        );
        let elf32 = tls_segment_metadata(
            1,
            0x100,
            0x10,
            0x400000,
            0x20,
            0x10,
            4,
            location.clone(),
            Some(location),
        );

        assert_eq!(elf64.memory_size, "0x40");
        assert_eq!(elf64.alignment, "0x20");
        assert_eq!(elf64.source_location.as_ref().unwrap().offset, "0x40");
        assert!(!elf64.malformed);
        assert_eq!(elf32.virtual_address, "0x400000");
        assert!(!elf32.malformed);
    }

    #[test]
    fn preserves_invalid_tls_extent_and_alignment_reasons() {
        let location = Range {
            offset: "0x40".into(),
            bytes: "0x38".into(),
        };
        let extent = tls_segment_metadata(
            0,
            0,
            0x20,
            0,
            0x10,
            0x20,
            0,
            location.clone(),
            Some(location.clone()),
        );
        let alignment = tls_segment_metadata(
            0,
            0,
            0,
            0,
            0,
            3,
            0,
            location,
            Some(Range {
                offset: "0x40".into(),
                bytes: "0x0".into(),
            }),
        );

        assert!(extent.malformed);
        assert_eq!(extent.unknown_reason, Some("invalid-tls-memory-extent"));
        assert!(alignment.malformed);
        assert_eq!(alignment.unknown_reason, Some("invalid-tls-alignment"));
    }

    #[test]
    fn projects_eh_frame_source_range_and_extent() {
        let source = Range {
            offset: "0x200".into(),
            bytes: "0x30".into(),
        };
        let metadata =
            eh_frame_segment_metadata(3, 0x200, 0x30, 0x400200, 0x30, 0x10, 4, Some(source));

        assert_eq!(metadata.segment_index, 3);
        assert_eq!(metadata.virtual_address, "0x400200");
        assert_eq!(metadata.source_location.unwrap().bytes, "0x30");
        assert!(!metadata.malformed);
    }

    #[test]
    fn preserves_malformed_eh_frame_reasons() {
        let metadata = eh_frame_segment_metadata(0, 0, 0x20, 0, 0x10, 3, 0, None);

        assert!(metadata.malformed);
        assert_eq!(
            metadata.unknown_reason,
            Some("eh-frame-range-outside-snapshot")
        );
    }

    #[test]
    fn preserves_pt_interp_name_and_source_range() {
        let mut bytes = vec![0u8; 128];
        bytes[0..4].copy_from_slice(&3u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&64u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&8u64.to_le_bytes());
        bytes[64..72].copy_from_slice(b"/ld.so\0\0");

        let values = interpreters(&bytes, true, 0, 1, 56, 64).unwrap();

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].display, "/ld.so");
        assert_eq!(
            values[0].location.as_ref().map(|r| r.offset.as_str()),
            Some("0x40")
        );
        assert_eq!(values[0].unknown_reason, None);
    }

    #[test]
    fn preserves_big_endian_elf32_pt_interp_and_marks_missing_terminator() {
        let mut bytes = vec![0u8; 96];
        bytes[0..4].copy_from_slice(&3u32.to_be_bytes());
        bytes[4..8].copy_from_slice(&64u32.to_be_bytes());
        bytes[16..20].copy_from_slice(&7u32.to_be_bytes());
        bytes[64..71].copy_from_slice(b"ld-musl");

        let values = interpreters(&bytes, false, 0, 1, 32, 32).unwrap();

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].display, "ld-musl");
        assert_eq!(
            values[0].location.as_ref().map(|r| r.offset.as_str()),
            Some("0x40")
        );
        assert_eq!(
            values[0].unknown_reason.as_deref(),
            Some("PT_INTERP is not NUL-terminated")
        );
    }

    #[test]
    fn bounds_pt_interp_observation_but_preserves_declared_range() {
        let mut bytes = vec![b'a'; 4_200];
        bytes[0..4].copy_from_slice(&3u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&64u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&4_097u64.to_le_bytes());

        let values = interpreters(&bytes, true, 0, 1, 56, 64).unwrap();

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].display.len(), 4_096);
        assert_eq!(values[0].location.as_ref().unwrap().bytes, "0x1001");
        assert_eq!(
            values[0].unknown_reason.as_deref(),
            Some("PT_INTERP exceeds the bounded observation size")
        );
    }

    #[test]
    fn projects_dynamic_relocation_into_got_linkage() {
        let relocations = vec![
            Relocation {
                section_index: usize::MAX,
                entry_index: 0,
                reported_offset: "0x401000".into(),
                target: RelocationTarget::LinkedVirtualAddress {
                    address: "0x401000".into(),
                },
                location: Range {
                    offset: "0x20".into(),
                    bytes: "0x18".into(),
                },
                kind: 6,
                symbol_table_index: 0,
                symbol_index: 1,
                symbol_reference_meaning: "symbol-table-entry",
                addend: None,
                symbol: Some(Name {
                    display: "puts".into(),
                    bytes_base64: None,
                    location: None,
                    unknown_reason: None,
                }),
                symbol_version: None,
                symbol_version_hidden: false,
                symbol_resolution: "resolved",
            },
            Relocation {
                section_index: usize::MAX,
                entry_index: 1,
                reported_offset: "0x401008".into(),
                target: RelocationTarget::LinkedVirtualAddress {
                    address: "0x401008".into(),
                },
                location: Range {
                    offset: "0x38".into(),
                    bytes: "0x18".into(),
                },
                kind: 7,
                symbol_table_index: 0,
                symbol_index: 2,
                symbol_reference_meaning: "symbol-table-entry",
                addend: None,
                symbol: Some(Name {
                    display: "printf".into(),
                    bytes_base64: None,
                    location: None,
                    unknown_reason: None,
                }),
                symbol_version: None,
                symbol_version_hidden: false,
                symbol_resolution: "resolved",
            },
        ];

        let (got, plt) = dynamic_linkage_maps(&relocations);

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].display_name, "puts");
        assert_eq!(got[0].address, "0x401000");
        assert_eq!(plt.len(), 1);
        assert_eq!(plt[0].display_name, "printf");
    }

    #[test]
    fn resolves_section_backed_gnu_symbol_version() {
        let mut bytes = vec![0u8; 42];
        bytes[28..37].copy_from_slice(b"\0VER_1\0\0\0");

        bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&0u16.to_le_bytes());
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&20u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
        bytes[40..42].copy_from_slice(&2u16.to_le_bytes());

        let raw = vec![
            (0x6ffffffd, 0, 0, 0, 28, 1, 0, 4, 20, 0),
            (3, 0, 0, 28, 9, 0, 0, 1, 1, 0),
            (2, 0, 0, 0, 0, 0, 0, 4, 0, 0),
            (0x6fffffff, 0, 0, 40, 2, 2, 0, 2, 2, 0),
        ];
        let mut symbols = vec![Symbol {
            table_index: 2,
            entry_index: 0,
            name: Name {
                display: "symbol".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            location: Range {
                offset: "0x0".into(),
                bytes: "0x0".into(),
            },
            value: "0x0".into(),
            value_meaning: "undefined",
            size: "0x0".into(),
            binding: "STB_GLOBAL".into(),
            kind: "STT_NOTYPE".into(),
            visibility: "STV_DEFAULT".into(),
            section_index: "0".into(),
            reported_section_index: "0".into(),
            version: None,
            version_index: None,
            version_location: None,
            version_state: "unknown",
            version_hidden: false,
        }];

        attach_section_versions(&bytes, &raw, true, &mut symbols).unwrap();

        assert_eq!(symbols[0].version.as_deref(), Some("VER_1"));
        assert_eq!(symbols[0].version_index, Some(2));
        assert_eq!(symbols[0].version_state, "resolved");
        assert_eq!(
            symbols[0]
                .version_location
                .as_ref()
                .map(|r| r.offset.as_str()),
            Some("0x28")
        );
        assert!(!symbols[0].version_hidden);

        let tables = gnu_version_tables(&bytes, &raw, true)
            .unwrap()
            .expect("version definition table");
        assert_eq!(tables.definitions.len(), 1);
        assert_eq!(tables.definitions[0].index, 2);
        assert_eq!(tables.definitions[0].auxiliary_names, vec!["VER_1"]);
        assert!(!tables.malformed);

        let mut truncated = raw;
        truncated[3].4 = 0;
        symbols[0].version_state = "unknown";
        symbols[0].version = None;
        symbols[0].version_index = None;
        symbols[0].version_location = None;
        attach_section_versions(&bytes, &truncated, true, &mut symbols).unwrap();
        assert_eq!(symbols[0].version_state, "malformed");
    }

    #[test]
    fn ignores_truncated_gnu_version_definition() {
        let bytes = vec![0u8; 8];
        let raw = vec![(0x6ffffffd, 0, 0, 0, 20, 0, 0, 4, 20, 0)];

        assert!(gnu_version_names(&bytes, &raw, true).unwrap().is_empty());
        let tables = gnu_version_tables(&bytes, &raw, true)
            .unwrap()
            .expect("malformed version table fact");
        assert!(tables.malformed);
    }

    #[test]
    fn resolves_dynamic_symbol_version_through_pt_load_mapping() {
        let mut bytes = vec![0u8; 50];
        bytes[0..4].copy_from_slice(b"VER\0");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[26..28].copy_from_slice(&2u16.to_le_bytes());
        bytes[34..38].copy_from_slice(&20u32.to_le_bytes());
        bytes[38..42].copy_from_slice(&0u32.to_le_bytes());

        let mut symbols = vec![Symbol {
            table_index: 0,
            entry_index: 0,
            name: Name {
                display: "symbol".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            location: Range {
                offset: "0x0".into(),
                bytes: "0x0".into(),
            },
            value: "0x0".into(),
            value_meaning: "undefined",
            size: "0x0".into(),
            binding: "STB_GLOBAL".into(),
            kind: "STT_NOTYPE".into(),
            visibility: "STV_DEFAULT".into(),
            section_index: "0".into(),
            reported_section_index: "0".into(),
            version: None,
            version_index: None,
            version_location: None,
            version_state: "unknown",
            version_hidden: false,
        }];

        attach_dynamic_versions(
            &bytes,
            &[(0x1000, 0x300, 0)],
            0x1000,
            4,
            Some(0x1010),
            Some(0x1016),
            Some(1),
            None,
            None,
            true,
            &mut symbols,
        )
        .unwrap();

        assert_eq!(symbols[0].version.as_deref(), Some("VER"));
        assert_eq!(symbols[0].version_index, Some(2));
        assert_eq!(symbols[0].version_state, "resolved");
        assert_eq!(
            symbols[0]
                .version_location
                .as_ref()
                .map(|r| r.offset.as_str()),
            Some("0x10")
        );
        assert!(!symbols[0].version_hidden);

        bytes[16..18].copy_from_slice(&0x8000u16.to_le_bytes());
        symbols[0].version_state = "unknown";
        symbols[0].version = None;
        symbols[0].version_index = None;
        symbols[0].version_location = None;
        attach_dynamic_versions(
            &bytes,
            &[(0x1000, 0x300, 0)],
            0x1000,
            4,
            Some(0x1010),
            Some(0x1016),
            Some(1),
            None,
            None,
            true,
            &mut symbols,
        )
        .unwrap();
        assert_eq!(symbols[0].version_index, Some(0x8000));
        assert_eq!(symbols[0].version_state, "unversioned");
        assert!(symbols[0].version_hidden);

        symbols[0].entry_index = 100;
        symbols[0].version_state = "unknown";
        symbols[0].version = None;
        symbols[0].version_index = None;
        symbols[0].version_location = None;
        attach_dynamic_versions(
            &bytes,
            &[(0x1000, 0x300, 0)],
            0x1000,
            4,
            Some(0x1010),
            Some(0x1016),
            Some(1),
            None,
            None,
            true,
            &mut symbols,
        )
        .unwrap();
        assert_eq!(symbols[0].version_state, "malformed");
    }

    #[test]
    fn expands_bounded_relr_bitmap_entries() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1000u64.to_le_bytes());
        bytes.extend_from_slice(&(1u64 | (1 << 1) | (1 << 3)).to_le_bytes());
        let sections = vec![(19, 0, 0, 0, 16, 0, 0, 8, 8, 0)];

        let packed = section_relr(&bytes, &sections, true, 64).unwrap();

        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0].entries.len(), 3);
        assert_eq!(packed[0].entries[0].reported_offset, "0x1000");
        assert_eq!(packed[0].entries[1].reported_offset, "0x1008");
        assert_eq!(packed[0].entries[2].reported_offset, "0x1018");
    }

    #[test]
    fn validates_relocation_symbol_indices_against_linked_table_bounds() {
        let sections = vec![(11, 0, 0, 0, 48, 0, 0, 8, 24, 0)];

        validate_relocation_symbol_index(&sections, 0, 1).unwrap();
        let error = validate_relocation_symbol_index(&sections, 0, 2).unwrap_err();
        assert!(matches!(
            error,
            Error::Format("ELF relocation references a missing symbol")
        ));
    }

    #[test]
    fn rejects_relocations_linked_to_non_symbol_sections() {
        let sections = vec![(1, 0, 0, 0, 32, 0, 0, 1, 0, 0)];

        let error = validate_relocation_symbol_index(&sections, 0, 1).unwrap_err();
        assert!(matches!(
            error,
            Error::Format("ELF relocation link does not identify a symbol table")
        ));
    }

    #[test]
    fn rejects_relocations_with_missing_rel_target_sections() {
        let error = validate_relocation_target_section(1, 3, 2).unwrap_err();
        assert!(matches!(
            error,
            Error::Format("ELF relocation references a missing target section")
        ));
        validate_relocation_target_section(3, 3, 2).unwrap();
    }

    #[test]
    fn validates_symbol_tables_link_to_string_tables() {
        let sections = vec![
            (2, 0, 0, 0, 24, 1, 0, 8, 24, 0),
            (3, 0, 0, 24, 4, 0, 0, 1, 0, 0),
        ];
        assert_eq!(validate_symbol_string_table(&sections, 1).unwrap(), (24, 4));

        let invalid = vec![(2, 0, 0, 0, 24, 0, 0, 8, 24, 0)];
        let error = validate_symbol_string_table(&invalid, 0).unwrap_err();
        assert!(matches!(
            error,
            Error::Format("ELF symbol table links to an invalid string table")
        ));
    }

    #[test]
    fn rejects_symbol_tables_with_short_or_partial_entries() {
        let short_entry = validate_symbol_table_layout(
            23,
            46,
            24,
            "ELF symbol entry is smaller than the decoded Elf64_Sym structure.",
        )
        .unwrap_err();
        assert!(matches!(
            short_entry,
            Error::Format("ELF symbol entry is smaller than the decoded Elf64_Sym structure.")
        ));

        let partial_entry = validate_symbol_table_layout(
            24,
            25,
            24,
            "ELF symbol entry is smaller than the decoded Elf64_Sym structure.",
        )
        .unwrap_err();
        assert!(matches!(
            partial_entry,
            Error::Format("ELF symbol table size is not entry-aligned")
        ));

        validate_symbol_table_layout(
            16,
            32,
            16,
            "ELF32 symbol entry is smaller than the decoded Elf32_Sym structure.",
        )
        .unwrap();
    }

    #[test]
    fn rejects_relr_bitmap_without_base() {
        let bytes = (1u64 | (1 << 1)).to_le_bytes();
        let sections = vec![(19, 0, 0, 0, 8, 0, 0, 8, 8, 0)];

        assert!(section_relr(&bytes, &sections, true, 64).is_err());
    }

    #[test]
    fn decodes_gnu_build_id_core_note() {
        let decoded = decode_core_note(b"GNU\0", &[1, 2, 3], 3, true, 64);

        assert!(matches!(
            decoded,
            Some(DecodedNote::GnuBuildId { build_id_base64 })
                if !build_id_base64.is_empty()
        ));
    }

    #[test]
    fn honors_section_note_alignment_for_elf64_records() {
        let mut bytes = vec![0u8; 40];
        let mut write_note = |offset: usize, descriptor: [u8; 4]| {
            bytes[offset..offset + 4].copy_from_slice(&4u32.to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&4u32.to_le_bytes());
            bytes[offset + 8..offset + 12].copy_from_slice(&3u32.to_le_bytes());
            bytes[offset + 12..offset + 16].copy_from_slice(b"GNU\0");
            bytes[offset + 16..offset + 20].copy_from_slice(&descriptor);
        };
        write_note(0, [1, 2, 3, 4]);
        write_note(20, [5, 6, 7, 8]);

        let sections = vec![(7, 0, 0, 0, 40, 0, 0, 4, 0, 0)];
        let notes = notes_from_sections(&bytes, &sections, true, 64).unwrap();

        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].location.offset, "0x0");
        assert_eq!(notes[0].location.bytes, "0x14");
        assert_eq!(notes[1].location.offset, "0x14");
        assert_eq!(notes[1].location.bytes, "0x14");
    }

    #[test]
    fn decodes_gnu_abi_tag_little_and_big_endian() {
        let mut little = Vec::new();
        for value in [0u32, 2, 39, 1] {
            little.extend_from_slice(&value.to_le_bytes());
        }
        let mut big = Vec::new();
        for value in [3u32, 1, 2, 3] {
            big.extend_from_slice(&value.to_be_bytes());
        }

        assert!(matches!(
            decode_core_note(b"GNU\0", &little, 1, true, 64),
            Some(DecodedNote::GnuAbiTag {
                os,
                major,
                minor,
                subminor,
                malformed: false,
            }) if os == "GNU_ABI_TAG_OS_LINUX"
                && major == "0x2"
                && minor == "0x27"
                && subminor == "0x1"
        ));
        assert!(matches!(
            decode_core_note(b"GNU\0", &big, 1, false, 32),
            Some(DecodedNote::GnuAbiTag { os, .. })
                if os == "GNU_ABI_TAG_OS_FREEBSD"
        ));
    }

    #[test]
    fn retains_truncated_gnu_abi_tag_as_malformed() {
        assert!(matches!(
            decode_core_note(b"GNU\0", &[0, 0, 0, 0], 1, true, 64),
            Some(DecodedNote::GnuAbiTag {
                malformed: true,
                ..
            })
        ));
    }

    #[test]
    fn retains_oversized_gnu_abi_tag_as_malformed() {
        let mut descriptor = vec![0u8; 16];
        descriptor.push(0);

        assert!(matches!(
            decode_core_note(b"GNU\0", &descriptor, 1, true, 64),
            Some(DecodedNote::GnuAbiTag {
                malformed: true,
                ..
            })
        ));
    }

    #[test]
    fn decodes_bounded_nt_file_mappings() {
        let mut descriptor = vec![0u8; 16 * 3 + 16];
        descriptor[0..8].copy_from_slice(&1u64.to_le_bytes());
        descriptor[8..16].copy_from_slice(&4096u64.to_le_bytes());
        descriptor[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        descriptor[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        descriptor[32..40].copy_from_slice(&0u64.to_le_bytes());
        descriptor[40..47].copy_from_slice(b"/bin/x\0");

        let decoded = decode_core_note(
            &[b'C', b'O', b'R', b'E', 0],
            &descriptor,
            0x46494c45,
            true,
            64,
        );

        assert!(matches!(
            decoded,
            Some(DecodedNote::NtFile { mappings, malformed: false, .. })
                if mappings.len() == 1 && mappings[0].path == "/bin/x"
        ));
    }

    #[test]
    fn decodes_gnu_property_bits_and_unknown_values() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&0xc0000002u32.to_le_bytes());
        descriptor.extend_from_slice(&4u32.to_le_bytes());
        descriptor.extend_from_slice(&3u32.to_le_bytes());
        descriptor.extend_from_slice(&[0u8; 4]);
        descriptor.extend_from_slice(&0xdeadbeefu32.to_le_bytes());
        descriptor.extend_from_slice(&4u32.to_le_bytes());
        descriptor.extend_from_slice(&0xdeadbeefu32.to_le_bytes());
        descriptor.extend_from_slice(&[0u8; 4]);

        let decoded = decode_core_note(b"GNU\0", &descriptor, 5, true, 64);

        assert!(matches!(
            decoded,
            Some(DecodedNote::GnuProperty { properties, malformed: false })
                if properties.len() == 2
                    && properties[0].named_bits == vec!["x86-ibt", "x86-shstk"]
                    && properties[1].property_type == 0xdeadbeef
                    && properties[1].unknown_bits == vec!["0xdeadbeef"]
        ));
    }

    #[test]
    fn decodes_x86_isa_levels_and_preserves_unknown_bits() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&0xc0008001u32.to_le_bytes());
        descriptor.extend_from_slice(&4u32.to_le_bytes());
        descriptor.extend_from_slice(&(1u32 | 512 | (1 << 31)).to_le_bytes());
        descriptor.extend_from_slice(&[0u8; 4]);

        let decoded = decode_core_note(b"GNU\0", &descriptor, 5, true, 64);

        assert!(matches!(
            decoded,
            Some(DecodedNote::GnuProperty { properties, malformed: false })
                if properties[0].named_bits
                    == vec!["x86-486", "x86-avx"]
                    && properties[0].unknown_bits == vec!["0x80000000"]
        ));
    }

    #[test]
    fn retains_truncated_gnu_property_note_as_malformed() {
        let descriptor = [2u8, 0, 0, 0, 8, 0, 0, 0, 1, 2, 3];

        assert!(matches!(
            decode_core_note(b"GNU\0", &descriptor, 5, true, 64),
            Some(DecodedNote::GnuProperty {
                malformed: true,
                ..
            })
        ));
    }

    #[test]
    fn decodes_big_endian_aarch64_property_bits() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&0xc0000000u32.to_be_bytes());
        descriptor.extend_from_slice(&4u32.to_be_bytes());
        descriptor.extend_from_slice(&3u32.to_be_bytes());
        descriptor.extend_from_slice(&[0, 0, 0, 0]);

        let decoded = decode_core_note(b"GNU\0", &descriptor, 5, false, 64);

        assert!(matches!(
            decoded,
            Some(DecodedNote::GnuProperty { properties, malformed: false })
                if properties[0].named_bits == vec!["aarch64-bti", "aarch64-pac"]
                    && properties[0].descriptor_offset == "0x8"
                    && !properties[0].malformed
        ));
    }

    #[test]
    fn decodes_gnu_property_program_header_for_elf32() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&0x6474_e553u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&32u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&32u32.to_le_bytes());

        bytes[32..36].copy_from_slice(&4u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&16u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&5u32.to_le_bytes());
        bytes[44..48].copy_from_slice(b"GNU\0");
        bytes[48..52].copy_from_slice(&0xc0000002u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&4u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&1u32.to_le_bytes());

        let notes = notes_from_segments(&bytes, true, 0, 1, 32, 32).unwrap();

        assert!(matches!(
            &notes[..],
            [Note {
                name,
                note_type: 5,
                location,
                decoded: Some(DecodedNote::GnuProperty { properties, malformed: false }),
                ..
            }] if name == "GNU"
                && location.offset == "0x20"
                && location.bytes == "0x20"
                && properties.len() == 1
                && properties[0].named_bits == vec!["x86-ibt"]
                && properties[0].location.offset == "0x0"
                && properties[0].location.bytes == "0x10"
        ));
    }

    #[test]
    fn decodes_gnu_property_program_header_for_elf64() {
        let mut bytes = vec![0u8; 88];
        bytes[0..4].copy_from_slice(&0x6474_e553u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&56u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&32u64.to_le_bytes());

        bytes[56..60].copy_from_slice(&4u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&16u32.to_le_bytes());
        bytes[64..68].copy_from_slice(&5u32.to_le_bytes());
        bytes[68..72].copy_from_slice(b"GNU\0");
        bytes[72..76].copy_from_slice(&0xc0000002u32.to_le_bytes());
        bytes[76..80].copy_from_slice(&4u32.to_le_bytes());
        bytes[80..84].copy_from_slice(&3u32.to_le_bytes());

        let notes = notes_from_segments(&bytes, true, 0, 1, 56, 64).unwrap();

        assert!(matches!(
            &notes[..],
            [Note {
                name,
                note_type: 5,
                location,
                decoded: Some(DecodedNote::GnuProperty { properties, malformed: false }),
                ..
            }] if name == "GNU"
                && location.offset == "0x38"
                && location.bytes == "0x20"
                && properties.len() == 1
                && properties[0].named_bits == vec!["x86-ibt", "x86-shstk"]
                && properties[0].location.offset == "0x0"
                && properties[0].location.bytes == "0x10"
        ));
    }

    #[test]
    fn marks_gnu_property_with_unsupported_payload_width() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&0xc0000002u32.to_le_bytes());
        descriptor.extend_from_slice(&2u32.to_le_bytes());
        descriptor.extend_from_slice(&[1, 0]);

        let decoded = decode_core_note(b"GNU\0", &descriptor, 5, true, 32);

        assert!(matches!(
            decoded,
            Some(DecodedNote::GnuProperty { properties, malformed: true })
                if properties[0].malformed && properties[0].named_bits.is_empty()
        ));
    }

    #[test]
    fn preserves_duplicate_gnu_properties_and_conflicting_bits_in_order() {
        let mut descriptor = Vec::new();
        for value in [1u32, 2u32] {
            descriptor.extend_from_slice(&0xc0000002u32.to_le_bytes());
            descriptor.extend_from_slice(&4u32.to_le_bytes());
            descriptor.extend_from_slice(&value.to_le_bytes());
            descriptor.extend_from_slice(&[0u8; 4]);
        }

        let decoded = decode_core_note(b"GNU\0", &descriptor, 5, true, 64);

        assert!(matches!(
            decoded,
            Some(DecodedNote::GnuProperty { properties, malformed: false })
                if properties.len() == 2
                    && properties[0].named_bits == vec!["x86-ibt"]
                    && properties[1].named_bits == vec!["x86-shstk"]
        ));
    }

    #[test]
    fn marks_missing_gnu_property_alignment_padding() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&0xc0000002u32.to_le_bytes());
        descriptor.extend_from_slice(&4u32.to_le_bytes());
        descriptor.extend_from_slice(&1u32.to_le_bytes());

        let decoded = decode_core_note(b"GNU\0", &descriptor, 5, true, 32);

        assert!(matches!(
            decoded,
            Some(DecodedNote::GnuProperty { properties, malformed: true })
                if properties.len() == 1 && !properties[0].malformed
        ));
    }

    #[test]
    fn decodes_debuglink_crc_and_filename_bytes() {
        let mut bytes = b"dbg\0".to_vec();
        bytes.extend_from_slice(&0x12345678u32.to_le_bytes());
        let sections = vec![Section {
            index: 0,
            name: Name {
                display: ".gnu_debuglink".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            kind: "SHT_PROGBITS".into(),
            header_location: Range {
                offset: "0x0".into(),
                bytes: "0x0".into(),
            },
            address: "0x0".into(),
            offset: "0x0".into(),
            size: "0x8".into(),
            alignment: "0x1".into(),
            flags: "0x0".into(),
            link: 0,
            info: 0,
            entry_size: "0x0".into(),
            file_backing: "file",
            compression: None,
        }];
        let links = debug_links_from_sections(&bytes, &sections, true).unwrap();
        assert_eq!(links[0].filename, "dbg");
        assert_eq!(links[0].crc32.as_deref(), Some("0x12345678"));
        assert_eq!(links[0].crc32_location.as_ref().unwrap().offset, "0x4");
        assert_eq!(links[0].crc32_location.as_ref().unwrap().bytes, "0x4");
        assert!(!links[0].malformed);
    }

    #[test]
    fn preserves_debugaltlink_build_id_source_range() {
        let bytes = b"alt\0\x01\x02\x03\x04";
        let sections = vec![Section {
            index: 0,
            name: Name {
                display: ".gnu_debugaltlink".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            kind: "SHT_PROGBITS".into(),
            header_location: Range {
                offset: "0x0".into(),
                bytes: "0x0".into(),
            },
            address: "0x0".into(),
            offset: "0x0".into(),
            size: "0x8".into(),
            alignment: "0x1".into(),
            flags: "0x0".into(),
            link: 0,
            info: 0,
            entry_size: "0x0".into(),
            file_backing: "file",
            compression: None,
        }];

        let links = debug_links_from_sections(bytes, &sections, true).unwrap();

        assert_eq!(links[0].build_id_base64.as_deref(), Some("AQIDBA=="));
        assert_eq!(links[0].build_id_location.as_ref().unwrap().offset, "0x4");
        assert_eq!(links[0].build_id_location.as_ref().unwrap().bytes, "0x4");
        assert!(!links[0].malformed);
    }

    #[test]
    fn marks_empty_debuglink_filename_malformed() {
        let bytes = b"\0\0\0\0\0\0\0\0";
        let sections = vec![Section {
            index: 0,
            name: Name {
                display: ".gnu_debuglink".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            kind: "SHT_PROGBITS".into(),
            header_location: Range {
                offset: "0x0".into(),
                bytes: "0x0".into(),
            },
            address: "0x0".into(),
            offset: "0x0".into(),
            size: "0x8".into(),
            alignment: "0x1".into(),
            flags: "0x0".into(),
            link: 0,
            info: 0,
            entry_size: "0x0".into(),
            file_backing: "file",
            compression: None,
        }];

        let links = debug_links_from_sections(bytes, &sections, true).unwrap();
        assert!(links[0].malformed);
        assert_eq!(links[0].unknown_reason, Some("empty-debug-link-filename"));
    }

    #[test]
    fn decodes_big_endian_debuglink_checksum_and_preserves_range() {
        let mut bytes = b"dbg-be\0".to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&[0, 0, 0, 0x2a]);
        let sections = vec![Section {
            index: 0,
            name: Name {
                display: ".gnu_debuglink".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            kind: "SHT_PROGBITS".into(),
            header_location: Range {
                offset: "0x20".into(),
                bytes: "0x0".into(),
            },
            address: "0x0".into(),
            offset: "0x0".into(),
            size: "0xc".into(),
            alignment: "0x1".into(),
            flags: "0x0".into(),
            link: 0,
            info: 0,
            entry_size: "0x0".into(),
            file_backing: "file",
            compression: None,
        }];

        let links = debug_links_from_sections(&bytes, &sections, false).unwrap();

        assert_eq!(links[0].crc32.as_deref(), Some("0x2a"));
        assert_eq!(links[0].filename_base64, "ZGJnLWJl");
        assert_eq!(links[0].location.offset, "0x0");
    }

    #[test]
    fn preserves_missing_debuglink_terminator_as_malformed() {
        let sections = vec![Section {
            index: 0,
            name: Name {
                display: ".gnu_debuglink".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            kind: "SHT_PROGBITS".into(),
            header_location: Range {
                offset: "0x0".into(),
                bytes: "0x0".into(),
            },
            address: "0x0".into(),
            offset: "0x0".into(),
            size: "0x4".into(),
            alignment: "0x1".into(),
            flags: "0x0".into(),
            link: 0,
            info: 0,
            entry_size: "0x0".into(),
            file_backing: "file",
            compression: None,
        }];

        let links = debug_links_from_sections(b"name", &sections, true).unwrap();

        assert!(links[0].malformed);
        assert_eq!(
            links[0].unknown_reason,
            Some("missing-null-terminated-filename")
        );
    }

    #[test]
    fn marks_truncated_debugaltlink_malformed() {
        let sections = vec![Section {
            index: 0,
            name: Name {
                display: ".gnu_debugaltlink".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            kind: "SHT_PROGBITS".into(),
            header_location: Range {
                offset: "0x0".into(),
                bytes: "0x4".into(),
            },
            address: "0x0".into(),
            offset: "0x0".into(),
            size: "0x4".into(),
            alignment: "0x1".into(),
            flags: "0x0".into(),
            link: 0,
            info: 0,
            entry_size: "0x0".into(),
            file_backing: "file",
            compression: None,
        }];
        let links = debug_links_from_sections(b"x\0\0\0", &sections, true).unwrap();
        assert!(links[0].malformed);
        assert_eq!(
            links[0].unknown_reason,
            Some("missing-debugaltlink-build-id")
        );
    }

    #[test]
    fn resolves_extended_symbol_section_index() {
        let bytes = 42u32.to_le_bytes();
        let sections = vec![(18, 0, 0, 0, 4, 0, 0, 4, 4, 0)];
        let indices = extended_symbol_indices(&bytes, &sections, 0, 1, true)
            .unwrap()
            .unwrap();
        assert_eq!(indices, vec![42]);
    }

    #[test]
    fn rejects_truncated_extended_symbol_indices() {
        let bytes = [0u8; 2];
        let sections = vec![(18, 0, 0, 0, 2, 0, 0, 4, 4, 0)];
        assert!(extended_symbol_indices(&bytes, &sections, 0, 1, true).is_err());
    }

    #[test]
    fn resolves_elf32_extended_numbering_from_section_zero() {
        let mut bytes = elf32_header(false);
        bytes.resize(92, 0);
        bytes[32..36].copy_from_slice(&52u32.to_le_bytes());
        bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
        bytes[48..50].copy_from_slice(&0u16.to_le_bytes());
        bytes[50..52].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[44..46].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[72..76].copy_from_slice(&1u32.to_le_bytes());

        let layout = read(&bytes).unwrap();

        assert_eq!(layout.sections.len(), 1);
        assert_eq!(
            layout.extended_numbering.as_ref().unwrap().section_count,
            Some(1)
        );
        assert_eq!(
            layout.extended_numbering.as_ref().unwrap().program_count,
            Some(0)
        );
        assert_eq!(
            layout
                .extended_numbering
                .as_ref()
                .unwrap()
                .section_name_index,
            Some(0)
        );
    }

    #[test]
    fn rejects_reserved_elf32_section_name_index() {
        let mut bytes = elf32_header(false);
        bytes[50..52].copy_from_slice(&0xff00u16.to_le_bytes());

        let error = read(&bytes).unwrap_err();

        assert!(matches!(
            error,
            Error::Format(
                "ELF32 section-name index is reserved and cannot directly reference a section"
            )
        ));
    }

    #[test]
    fn rejects_extended_section_name_index_without_section_zero() {
        let mut bytes = elf32_header(false);
        bytes[50..52].copy_from_slice(&0xffffu16.to_le_bytes());

        let error = read(&bytes).unwrap_err();

        assert!(matches!(
            error,
            Error::Format(
                "ELF32 extended section-name index requires a declared section-zero header"
            )
        ));
    }

    #[test]
    fn rejects_extended_section_name_index_resolved_to_ordinary_section() {
        let mut bytes = elf32_header(false);
        bytes.resize(92, 0);
        bytes[32..36].copy_from_slice(&52u32.to_le_bytes());
        bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
        bytes[48..50].copy_from_slice(&1u16.to_le_bytes());
        bytes[50..52].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[72..76].copy_from_slice(&1u32.to_le_bytes());
        bytes[76..80].copy_from_slice(&1u32.to_le_bytes());

        let error = read(&bytes).unwrap_err();

        assert!(matches!(
            error,
            Error::Format(
                "ELF32 SHN_XINDEX resolves to an ordinary section-name index; the escape requires an index at least SHN_LORESERVE"
            )
        ));
    }

    #[test]
    fn decodes_elf64_compression_header_without_decompression() {
        let mut bytes = vec![0u8; 24];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x4000u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&1u64.to_le_bytes());

        let compression = compressed_section(&bytes, 0x800, 0, 24, true, 64)
            .unwrap()
            .unwrap();

        assert_eq!(compression.algorithm, "zlib");
        assert_eq!(compression.raw_algorithm, "0x1");
        assert_eq!(compression.declared_uncompressed_size, "0x4000");
        assert!(!compression.malformed);
    }

    #[test]
    fn preserves_truncated_compression_header_reason() {
        let compression = compressed_section(&[1, 0, 0, 0], 0x800, 0, 4, true, 64)
            .unwrap()
            .unwrap();

        assert!(compression.malformed);
        assert_eq!(
            compression.unknown_reason,
            Some("truncated-compression-header")
        );
        assert_eq!(compression.raw_algorithm, "unknown");
    }

    #[test]
    fn preserves_unknown_compression_algorithm_code() {
        let mut bytes = vec![0u8; 24];
        bytes[0..4].copy_from_slice(&7u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&8u64.to_le_bytes());

        let compression = compressed_section(&bytes, 0x800, 0, 24, true, 64)
            .unwrap()
            .unwrap();

        assert_eq!(compression.algorithm, "unknown");
        assert_eq!(compression.raw_algorithm, "0x7");
        assert!(compression.malformed);
    }

    #[test]
    fn marks_reserved_gnu_stack_permission_bits_unknown() {
        assert_eq!(stack_policy_status(0x5), (false, None));
        assert_eq!(
            stack_policy_status(0x8),
            (true, Some("PT_GNU_STACK contains reserved permission bits"))
        );
    }

    #[test]
    fn projects_gnu_stack_header_and_duplicate_state() {
        let first = stack_policy_metadata(
            2,
            0x5,
            Range {
                offset: "0x80".into(),
                bytes: "0x38".into(),
            },
            false,
        );
        assert_eq!(first.policy, "executable");
        assert_eq!(first.flags, "0x5");
        assert_eq!(first.header_location.offset, "0x80");
        assert!(!first.duplicate);
        assert!(!first.malformed);

        let duplicate = stack_policy_metadata(
            4,
            0x4,
            Range {
                offset: "0x120".into(),
                bytes: "0x38".into(),
            },
            true,
        );
        assert!(duplicate.duplicate);
        assert!(duplicate.malformed);
        assert_eq!(
            duplicate.unknown_reason,
            Some("duplicate-PT_GNU_STACK-declaration")
        );
    }

    #[test]
    fn reports_nx_only_when_gnu_stack_policy_is_known() {
        let policy = stack_policy_metadata(
            0,
            0x4,
            Range {
                offset: "0x40".into(),
                bytes: "0x38".into(),
            },
            false,
        );
        assert_eq!(nx_mitigation(Some(&policy)), Some(true));
        assert_eq!(nx_mitigation(None), None);

        let malformed = stack_policy_metadata(
            1,
            0x8,
            Range {
                offset: "0x80".into(),
                bytes: "0x38".into(),
            },
            false,
        );
        assert_eq!(nx_mitigation(Some(&malformed)), None);
    }

    #[test]
    fn preserves_reserved_gnu_stack_bits_with_header_provenance() {
        let policy = stack_policy_metadata(
            1,
            0x8,
            Range {
                offset: "0x40".into(),
                bytes: "0x20".into(),
            },
            false,
        );

        assert!(policy.malformed);
        assert_eq!(
            policy.unknown_reason,
            Some("PT_GNU_STACK contains reserved permission bits")
        );
        assert_eq!(policy.header_location.bytes, "0x20");
    }

    #[test]
    fn decodes_section_group_members_and_unknown_signature() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&7u32.to_le_bytes());
        let mut sections = vec![(0, 0, 0, 0, 0, 0, 0, 0, 0, 0); 8];
        sections[0] = (17, 0, 0, 0, 12, 2, 9, 4, 4, 0);

        let groups = section_groups(&bytes, &sections, &[], true).unwrap();

        assert_eq!(groups[0].member_section_indices, vec![3, 7]);
        assert_eq!(groups[0].flags, "0x1");
        assert_eq!(
            groups[0].unknown_reason,
            Some("group-signature-symbol-unresolved")
        );
    }

    #[test]
    fn preserves_malformed_section_group_bounds() {
        let sections = vec![(17, 0, 0, 0, 2, 0, 0, 4, 4, 0)];

        let groups = section_groups(&[1, 0], &sections, &[], true).unwrap();

        assert!(groups[0].malformed);
        assert_eq!(
            groups[0].unknown_reason,
            Some("truncated-or-misaligned-group-table")
        );
    }

    #[test]
    fn preserves_out_of_range_section_group_members() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&9u32.to_le_bytes());
        let sections = vec![(17, 0, 0, 0, 8, 0, 0, 4, 4, 0)];

        let groups = section_groups(&bytes, &sections, &[], true).unwrap();

        assert_eq!(groups[0].member_section_indices, vec![9]);
        assert!(groups[0].malformed);
        assert_eq!(
            groups[0].unknown_reason,
            Some("group-member-index-out-of-range")
        );
    }

    fn pe_debug_fixture(is_pe32_plus: bool) -> Vec<u8> {
        let pe_offset = 0x80usize;
        let optional_size = if is_pe32_plus { 0xf0 } else { 0xe0 };
        let optional_offset = pe_offset + 24;
        let section_table = optional_offset + optional_size;
        let mut bytes = vec![0u8; 0x500];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&1u16.to_le_bytes());
        bytes[pe_offset + 20..pe_offset + 22]
            .copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[optional_offset..optional_offset + 2]
            .copy_from_slice(&(if is_pe32_plus { 0x20b } else { 0x10b } as u16).to_le_bytes());
        bytes[optional_offset + 60..optional_offset + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let directory_count_offset = optional_offset + if is_pe32_plus { 108 } else { 92 };
        bytes[directory_count_offset..directory_count_offset + 4]
            .copy_from_slice(&16u32.to_le_bytes());
        let debug_directory = optional_offset + if is_pe32_plus { 112 } else { 96 } + 6 * 8;
        bytes[debug_directory..debug_directory + 4].copy_from_slice(&0x300u32.to_le_bytes());
        bytes[debug_directory + 4..debug_directory + 8].copy_from_slice(&28u32.to_le_bytes());
        let security_directory = optional_offset + if is_pe32_plus { 112 } else { 96 } + 4 * 8;
        bytes[security_directory..security_directory + 4].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[security_directory + 4..security_directory + 8].copy_from_slice(&16u32.to_le_bytes());
        bytes[section_table + 8..section_table + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section_table + 12..section_table + 16].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section_table + 16..section_table + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section_table + 20..section_table + 24].copy_from_slice(&0x200u32.to_le_bytes());
        let entry = 0x300;
        bytes[entry + 4..entry + 8].copy_from_slice(&0x12345678u32.to_le_bytes());
        bytes[entry + 8..entry + 10].copy_from_slice(&1u16.to_le_bytes());
        bytes[entry + 10..entry + 12].copy_from_slice(&2u16.to_le_bytes());
        bytes[entry + 12..entry + 16].copy_from_slice(&2u32.to_le_bytes());
        bytes[entry + 16..entry + 20].copy_from_slice(&4u32.to_le_bytes());
        bytes[entry + 20..entry + 24].copy_from_slice(&0x320u32.to_le_bytes());
        bytes[entry + 24..entry + 28].copy_from_slice(&0x320u32.to_le_bytes());
        bytes[0x320..0x324].copy_from_slice(b"RSDS");
        bytes[0x400..0x404].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x404..0x406].copy_from_slice(&0x200u16.to_le_bytes());
        bytes[0x406..0x408].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x408..0x410].copy_from_slice(b"PKCS#7\0\0");
        bytes
    }

    #[test]
    fn projects_pe32_debug_directory_entry() {
        let entries = parse_pe_debug_directory(&pe_debug_fixture(false)).unwrap();

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.debug_type, "IMAGE_DEBUG_TYPE_CODEVIEW");
        assert_eq!(entry.raw_type, "0x2");
        assert_eq!(entry.timestamp, "0x12345678");
        assert_eq!(entry.major_version, 1);
        assert_eq!(entry.minor_version, 2);
        assert_eq!(entry.size_of_data, "0x4");
        assert_eq!(entry.data_rva, "0x320");
        assert_eq!(entry.file_pointer, "0x320");
        assert!(!entry.malformed);
        assert_eq!(entry.data_location.as_ref().unwrap().offset, "0x320");
    }

    #[test]
    fn projects_pe32_plus_debug_directory_entry() {
        let entries = parse_pe_debug_directory(&pe_debug_fixture(true)).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].debug_type, "IMAGE_DEBUG_TYPE_CODEVIEW");
        assert_eq!(
            entries[0].directory_location.as_ref().unwrap().offset,
            "0x300"
        );
    }

    #[test]
    fn projects_bounded_pe_resource_leaf_and_path() {
        let mut bytes = pe_debug_fixture(false);
        let optional = 0x98usize;
        let resource_directory = optional + 96 + 2 * 8;
        bytes[resource_directory..resource_directory + 4].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[resource_directory + 4..resource_directory + 8]
            .copy_from_slice(&0x100u32.to_le_bytes());

        bytes[0x20e..0x210].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x210..0x214].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x214..0x218].copy_from_slice(&0x8000_0020u32.to_le_bytes());
        bytes[0x220 + 12..0x220 + 14].copy_from_slice(&0u16.to_le_bytes());
        bytes[0x220 + 14..0x220 + 16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x230..0x234].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x234..0x238].copy_from_slice(&0x8000_0040u32.to_le_bytes());
        bytes[0x240 + 12..0x240 + 14].copy_from_slice(&0u16.to_le_bytes());
        bytes[0x240 + 14..0x240 + 16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x250..0x254].copy_from_slice(&3u32.to_le_bytes());
        bytes[0x254..0x258].copy_from_slice(&0xa0u32.to_le_bytes());
        bytes[0x280..0x284].copy_from_slice(b"DATA");
        bytes[0x2a0..0x2a4].copy_from_slice(&0x280u32.to_le_bytes());
        bytes[0x2a4..0x2a8].copy_from_slice(&4u32.to_le_bytes());
        bytes[0x2a8..0x2ac].copy_from_slice(&65001u32.to_le_bytes());

        let entries = parse_pe_resources(&bytes).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, vec!["id:1", "id:2", "id:3"]);
        assert_eq!(entries[0].data_rva, "0x280");
        assert_eq!(entries[0].data_size, "0x4");
        assert_eq!(entries[0].code_page, 65001);
        assert_eq!(entries[0].data_location.as_ref().unwrap().offset, "0x2a0");
        assert!(!entries[0].malformed);
    }

    #[test]
    fn preserves_invalid_pe_debug_data_range() {
        let mut bytes = pe_debug_fixture(false);
        bytes[0x318..0x31c].copy_from_slice(&0x900u32.to_le_bytes());
        let entries = parse_pe_debug_directory(&bytes).unwrap();

        assert!(entries[0].malformed);
        assert_eq!(
            entries[0].unknown_reason,
            Some("debug-data-range-outside-snapshot")
        );
        assert_eq!(entries[0].file_pointer, "0x900");
        assert!(entries[0].directory_location.is_some());
    }

    #[test]
    fn projects_pe_header_extent_and_entry_point_metadata() {
        let mut bytes = pe_debug_fixture(false);
        let optional = 0x98usize;
        bytes[optional + 16..optional + 20].copy_from_slice(&0x120u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 70..optional + 72].copy_from_slice(&0x8140u16.to_le_bytes());

        let metadata = parse_pe_header_metadata(&bytes).unwrap();

        assert_eq!(metadata.optional_magic, "0x10b");
        assert_eq!(metadata.entry_point_rva, "0x120");
        assert_eq!(metadata.size_of_image, "0x2000");
        assert_eq!(metadata.size_of_headers, "0x200");
        assert_eq!(metadata.subsystem, 3);
        assert_eq!(metadata.dll_characteristics, "0x8140");
        assert!(!metadata.malformed);
    }

    #[test]
    fn preserves_invalid_pe_entry_point_extent() {
        let mut bytes = pe_debug_fixture(false);
        let optional = 0x98usize;
        bytes[optional + 16..optional + 20].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());

        let metadata = parse_pe_header_metadata(&bytes).unwrap();

        assert!(metadata.malformed);
        assert_eq!(
            metadata.unknown_reason,
            Some("pe-entry-point-outside-image")
        );
        assert_eq!(metadata.entry_point_rva, "0x3000");
    }

    #[test]
    fn projects_pe32_security_directory_metadata_without_trust_claims() {
        let table = parse_pe_certificate_table(&pe_debug_fixture(false))
            .unwrap()
            .unwrap();

        assert_eq!(table.file_offset, "0x400");
        assert_eq!(table.declared_size, "0x10");
        assert_eq!(table.observed_size, "0x10");
        assert!(!table.malformed);
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].length, "0x10");
        assert_eq!(table.entries[0].revision, 0x200);
        assert_eq!(table.entries[0].certificate_type, 2);
        assert_eq!(
            table.entries[0].certificate_type_name,
            "WIN_CERT_TYPE_PKCS_SIGNED_DATA"
        );
        assert_eq!(table.entries[0].raw_base64, "UEtDUyM3AAA=");
    }

    #[test]
    fn preserves_unknown_pe_certificate_type_while_naming_known_types() {
        let mut bytes = pe_debug_fixture(false);
        bytes[0x406..0x408].copy_from_slice(&0x7777u16.to_le_bytes());

        let table = parse_pe_certificate_table(&bytes).unwrap().unwrap();

        assert_eq!(table.entries[0].certificate_type, 0x7777);
        assert_eq!(
            table.entries[0].certificate_type_name,
            "WIN_CERT_TYPE_UNKNOWN"
        );
    }

    #[test]
    fn projects_pe32_plus_security_directory_metadata() {
        let table = parse_pe_certificate_table(&pe_debug_fixture(true))
            .unwrap()
            .unwrap();

        assert_eq!(table.location.as_ref().unwrap().offset, "0x400");
        assert_eq!(table.entries[0].certificate_type, 2);
    }

    #[test]
    fn preserves_truncated_security_directory_range() {
        let mut bytes = pe_debug_fixture(false);
        let security_directory = 0x98 + 96 + 4 * 8;
        bytes[security_directory + 4..security_directory + 8]
            .copy_from_slice(&0x100u32.to_le_bytes());
        bytes.truncate(0x410);

        let table = parse_pe_certificate_table(&bytes).unwrap().unwrap();

        assert!(table.malformed);
        assert_eq!(
            table.unknown_reason,
            Some("certificate-table-truncated-or-resource-bounded")
        );
        assert_eq!(table.declared_size, "0x100");
        assert_eq!(table.observed_size, "0x10");
    }

    #[test]
    fn decodes_dynamic_flags_known_unknown_and_duplicate_values() {
        let (named, unknown) = dynamic_flag_bits(30, 1 | 8 | (1 << 31));
        assert_eq!(named, vec!["DF_ORIGIN", "DF_BIND_NOW"]);
        assert_eq!(unknown, vec!["0x80000000"]);

        let (first_named, _) = dynamic_flag_bits(0x6ffffffb, 1);
        let (second_named, _) = dynamic_flag_bits(0x6ffffffb, 8);
        assert_eq!(first_named, vec!["DF_1_NOW"]);
        assert_eq!(second_named, vec!["DF_1_NODELETE"]);
    }

    #[test]
    fn decodes_standalone_dynamic_policy_tags_without_dropping_raw_values() {
        let (textrel, textrel_unknown) = dynamic_flag_bits(22, 0);
        let (bind_now, bind_now_unknown) = dynamic_flag_bits(24, 0x7);

        assert_eq!(textrel, vec!["DT_TEXTREL"]);
        assert!(textrel_unknown.is_empty());
        assert_eq!(bind_now, vec!["DT_BIND_NOW"]);
        assert!(bind_now_unknown.is_empty());
    }

    #[test]
    fn preserves_dynamic_table_missing_null_terminator_as_malformed() {
        let mut bytes = vec![0u8; 0x100];
        bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x80u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&16u64.to_le_bytes());
        bytes[0x80..0x88].copy_from_slice(&30u64.to_le_bytes());
        bytes[0x88..0x90].copy_from_slice(&1u64.to_le_bytes());

        let dynamic = dynamic_flags(&bytes, true, 0, 1, 56, 64)
            .unwrap()
            .expect("PT_DYNAMIC metadata");

        assert!(dynamic.malformed);
        assert_eq!(dynamic.entries.len(), 1);
        assert_eq!(
            dynamic.unknown_reason,
            Some("dynamic-table-missing-null-terminator")
        );
    }

    #[test]
    fn bounds_dynamic_table_on_all_tags_including_unknown_entries() {
        const ENTRY_SIZE: usize = 16;
        const ENTRY_COUNT: usize = 16_385;
        let dynamic_size = ENTRY_SIZE * ENTRY_COUNT;
        let mut bytes = vec![0u8; 56 + dynamic_size];
        bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&(56u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(dynamic_size as u64).to_le_bytes());
        for entry in 0..ENTRY_COUNT {
            let offset = 56 + entry * ENTRY_SIZE;
            bytes[offset..offset + 8].copy_from_slice(&0x1234u64.to_le_bytes());
        }

        let dynamic = dynamic_flags(&bytes, true, 0, 1, 56, 64)
            .unwrap()
            .expect("PT_DYNAMIC metadata");

        assert!(dynamic.malformed);
        assert!(dynamic.entries.is_empty());
        assert_eq!(
            dynamic.unknown_reason,
            Some("dynamic-flag-entry-count-exceeded-bound")
        );
    }

    #[test]
    fn rejects_dependency_table_without_complete_null_terminator() {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x400000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x100u64.to_le_bytes());

        let dynamic_header = 56;
        bytes[dynamic_header..dynamic_header + 4].copy_from_slice(&2u32.to_le_bytes());
        bytes[dynamic_header + 8..dynamic_header + 16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[dynamic_header + 32..dynamic_header + 40].copy_from_slice(&16u64.to_le_bytes());
        bytes[0x100..0x108].copy_from_slice(&1u64.to_le_bytes());

        let error = dynamic_needed(&bytes, true, 0, 2, 56, 64).unwrap_err();
        assert!(matches!(
            error,
            Error::Format(
                "ELF dynamic segment has no complete DT_NULL terminator within its reported file range"
            )
        ));
    }

    #[test]
    fn rejects_dependency_table_without_string_table_tags() {
        let mut bytes = vec![0u8; 0x180];
        bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&32u64.to_le_bytes());
        bytes[0x100..0x108].copy_from_slice(&1u64.to_le_bytes());
        bytes[0x110..0x118].copy_from_slice(&0u64.to_le_bytes());

        let error = dynamic_needed(&bytes, true, 0, 1, 56, 64).unwrap_err();
        assert!(matches!(
            error,
            Error::Format("ELF dependency requires DT_STRTAB and DT_STRSZ")
        ));
    }

    fn gnu_hash_fixture(load_size: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 512];

        // PT_LOAD: virtual 0x400000 maps to file offset 0x100.
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x400000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&load_size.to_le_bytes());

        // PT_DYNAMIC, containing DT_GNU_HASH followed by DT_NULL.
        bytes[56..60].copy_from_slice(&2u32.to_le_bytes());
        bytes[64..72].copy_from_slice(&0x180u64.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x400080u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&32u64.to_le_bytes());
        bytes[0x180..0x188].copy_from_slice(&0x6ffffef5u64.to_le_bytes());
        bytes[0x188..0x190].copy_from_slice(&0x400020u64.to_le_bytes());

        // GNU hash header, one bloom word, one bucket, and one terminated chain.
        bytes[0x120..0x124].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x124..0x128].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x128..0x12c].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x12c..0x130].copy_from_slice(&5u32.to_le_bytes());
        bytes[0x138..0x13c].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x13c..0x140].copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    #[test]
    fn decodes_bounded_dynamic_gnu_hash_metadata() {
        let bytes = gnu_hash_fixture(0x80);
        let hash = dynamic_gnu_hash(&bytes, true, 0, 2, 56, 64)
            .unwrap()
            .expect("DT_GNU_HASH");

        assert_eq!(hash.bucket_count, Some(1));
        assert_eq!(hash.symbol_offset, Some(1));
        assert_eq!(hash.bloom_word_count, Some(1));
        assert_eq!(hash.symbol_count, Some(2));
        assert!(!hash.malformed);
        assert_eq!(
            hash.location.as_ref().map(|range| range.offset.as_str()),
            Some("0x120")
        );
        assert!(hash.bucket_location.is_some());
        assert!(hash.chain_location.is_some());
    }

    #[test]
    fn retains_truncated_dynamic_gnu_hash_as_malformed() {
        let bytes = gnu_hash_fixture(0x30);
        let hash = dynamic_gnu_hash(&bytes, true, 0, 2, 56, 64)
            .unwrap()
            .expect("DT_GNU_HASH");

        assert!(hash.malformed);
        assert_eq!(hash.symbol_count, None);
        assert_eq!(
            hash.unknown_reason,
            Some("GNU hash bloom or bucket table is truncated")
        );
    }

    #[test]
    fn projects_known_extended_program_header_kinds() {
        assert_eq!(segment_kind(7), "PT_TLS");
        assert_eq!(segment_kind(0x60000000), "PT_LOOS");
        assert_eq!(segment_kind(0x6fffffff), "PT_HIOS");
        assert_eq!(segment_kind(0x6474e550), "PT_GNU_EH_FRAME");
        assert_eq!(segment_kind(0x6474e553), "PT_GNU_PROPERTY");
        assert_eq!(segment_kind(0x1234), "PT_4660");
    }

    #[test]
    fn projects_standard_and_gnu_section_kinds() {
        assert_eq!(section_kind(7), "SHT_NOTE");
        assert_eq!(section_kind(14), "SHT_INIT_ARRAY");
        assert_eq!(section_kind(17), "SHT_GROUP");
        assert_eq!(section_kind(18), "SHT_SYMTAB_SHNDX");
        assert_eq!(section_kind(0x6ffffff6), "SHT_GNU_HASH");
        assert_eq!(section_kind(0x6fffffff), "SHT_GNU_VERSYM");
        assert_eq!(section_kind(0x1234), "SHT_4660");
    }

    #[test]
    fn projects_known_symbol_enums_and_preserves_unknown_values() {
        assert_eq!(symbol_binding(1), "STB_GLOBAL");
        assert_eq!(symbol_binding(10), "STB_GNU_UNIQUE");
        assert_eq!(symbol_binding(15), "STB_15");

        assert_eq!(symbol_type(2), "STT_FUNC");
        assert_eq!(symbol_type(10), "STT_GNU_IFUNC");
        assert_eq!(symbol_type(15), "STT_15");

        assert_eq!(symbol_visibility(2), "STV_HIDDEN");
        assert_eq!(symbol_visibility(7), "STV_7");
    }

    #[test]
    fn dynamic_relocations_classify_zero_symbol_indices_independently_of_type() {
        assert_eq!(relocation_symbol_reference_meaning(0), "zero-symbol-value");
        assert_eq!(relocation_symbol_reference_meaning(3), "symbol-table-entry");
    }

    #[test]
    fn decodes_bounded_nt_auxv_entries_and_retains_truncation() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&25u64.to_le_bytes());
        descriptor.extend_from_slice(&0x1234u64.to_le_bytes());
        descriptor.extend_from_slice(&0u64.to_le_bytes());
        descriptor.extend_from_slice(&0u64.to_le_bytes());

        let decoded = decode_nt_auxv(&descriptor, true, 64);
        match decoded {
            DecodedNote::NtAuxv { entries, malformed } => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].kind, "0x19");
                assert_eq!(entries[0].value, "0x1234");
                assert!(!malformed);
            }
            other => panic!("unexpected decoded note: {other:?}"),
        }

        let malformed = decode_nt_auxv(&descriptor[..descriptor.len() - 1], true, 64);
        assert!(matches!(
            malformed,
            DecodedNote::NtAuxv {
                malformed: true,
                ..
            }
        ));
    }

    #[test]
    fn decodes_nt_siginfo_leading_fields_and_partial_records() {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&11i32.to_le_bytes());
        descriptor.extend_from_slice(&(-1i32).to_le_bytes());
        descriptor.extend_from_slice(&3i32.to_le_bytes());

        assert!(matches!(
            decode_nt_siginfo(&descriptor, true),
            DecodedNote::NtSigInfo {
                signal: Some(11),
                errno: Some(-1),
                code: Some(3),
                malformed: false,
            }
        ));

        let partial = decode_nt_siginfo(&descriptor[..8], true);
        assert!(matches!(
            partial,
            DecodedNote::NtSigInfo {
                signal: Some(11),
                errno: Some(-1),
                code: None,
                malformed: true,
            }
        ));
    }

    #[test]
    fn preserves_nt_fpregset_size_without_guessing_register_layout() {
        assert!(matches!(
            decode_nt_fpregset(&[0xaa, 0xbb, 0xcc]),
            DecodedNote::NtFpRegSet {
                byte_length: 3,
                malformed: false,
            }
        ));
        assert!(matches!(
            decode_nt_fpregset(&[]),
            DecodedNote::NtFpRegSet {
                byte_length: 0,
                malformed: true,
            }
        ));
    }

    #[test]
    fn recognizes_dynamic_string_tags_with_unknown_tag_fallback() {
        for tag in [
            1, 14, 15, 29, 34, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff,
        ] {
            assert!(is_dynamic_string_tag(tag));
        }
        assert!(!is_dynamic_string_tag(0x1234));
        assert_eq!(dynamic_string_tag_name(1), "DT_NEEDED");
        assert_eq!(dynamic_string_tag_name(29), "DT_RUNPATH");
        assert_eq!(dynamic_string_tag_name(0x1234), "DT_UNKNOWN");
    }

    #[test]
    fn decodes_nt_prpsinfo_pid_and_command_with_class_aware_offsets() {
        let mut descriptor = vec![0u8; 56];
        descriptor[24..28].copy_from_slice(&4242i32.to_le_bytes());
        descriptor[40..47].copy_from_slice(b"worker\0");

        assert!(matches!(
            decode_nt_prpsinfo(&descriptor, true, 64),
            DecodedNote::NtPrPsInfo {
                pid: Some(4242),
                command: Some(command),
                malformed: false,
            } if command == "worker"
        ));

        assert!(matches!(
            decode_nt_prpsinfo(&descriptor[..24], true, 64),
            DecodedNote::NtPrPsInfo {
                pid: None,
                command: None,
                malformed: true,
            }
        ));
    }

    #[test]
    fn preserves_nt_taskstruct_size_without_kernel_layout_assumptions() {
        assert!(matches!(
            decode_nt_taskstruct(&[1, 2, 3, 4]),
            DecodedNote::NtTaskStruct {
                byte_length: 4,
                malformed: false,
            }
        ));
        assert!(matches!(
            decode_nt_taskstruct(&[]),
            DecodedNote::NtTaskStruct {
                byte_length: 0,
                malformed: true,
            }
        ));
    }

    #[test]
    fn carries_hidden_symbol_version_into_relocation_resolution() {
        let symbol = Symbol {
            table_index: 0,
            entry_index: 1,
            name: Name {
                display: "import".into(),
                bytes_base64: None,
                location: None,
                unknown_reason: None,
            },
            name_offset: "0x0".into(),
            location: Range {
                offset: "0x0".into(),
                bytes: "0x0".into(),
            },
            value: "0x0".into(),
            value_meaning: "undefined",
            size: "0x0".into(),
            binding: "STB_GLOBAL".into(),
            kind: "STT_FUNC".into(),
            visibility: "STV_DEFAULT".into(),
            section_index: "0".into(),
            reported_section_index: "0".into(),
            version: Some("VER_HIDDEN".into()),
            version_index: Some(2),
            version_location: None,
            version_state: "resolved",
            version_hidden: true,
        };
        let mut relocations = vec![Relocation {
            section_index: usize::MAX,
            entry_index: 0,
            reported_offset: "0x1000".into(),
            target: RelocationTarget::LinkedVirtualAddress {
                address: "0x1000".into(),
            },
            location: Range {
                offset: "0x0".into(),
                bytes: "0x10".into(),
            },
            kind: 7,
            symbol_table_index: 0,
            symbol_index: 1,
            symbol_reference_meaning: "symbol-table-entry",
            addend: None,
            symbol: None,
            symbol_version: None,
            symbol_version_hidden: false,
            symbol_resolution: "unresolved",
        }];

        attach_relocation_symbols(&mut relocations, &[symbol]);

        assert_eq!(relocations[0].symbol_version.as_deref(), Some("VER_HIDDEN"));
        assert!(relocations[0].symbol_version_hidden);
        assert_eq!(
            relocations[0].symbol_resolution,
            "resolved-versioned-symbol"
        );
    }

    #[test]
    fn distinguishes_unknown_symbol_version_from_known_unversioned_symbol() {
        assert_eq!(
            symbol_resolution_label(None, "unknown"),
            "resolved-symbol-version-unknown"
        );
        assert_eq!(
            symbol_resolution_label(None, "unversioned"),
            "resolved-symbol"
        );
        assert_eq!(
            symbol_resolution_label(Some("VER_1"), "resolved"),
            "resolved-versioned-symbol"
        );
    }
}
