//! Bounded, read-only Mach-O inspection.
//!
//! This reader deliberately keeps facts that can be decoded from load commands
//! without invoking Apple tooling. It rejects fat containers until an explicit
//! architecture selection is supplied by the caller.
pub mod dylib;
use serde::Serialize;
use std::fmt;

const MAX_COMMAND_BYTES: usize = 16 * 1024 * 1024;
const MAX_SYMBOLS: usize = 1_000_000;
const MAX_ARCHITECTURES: usize = 256;

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) | Self::Unsupported(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Serialize)]
pub struct Image {
    pub word_size: u8,
    pub endian: &'static str,
    pub cpu: u32,
    pub cpu_name: String,
    pub cpu_subtype: u32,
    pub cpu_subtype_name: String,
    pub file_type: u32,
    pub file_type_name: String,
    pub flags: u32,
    pub flag_names: Vec<String>,
    pub uuid: Option<String>,
    pub uuid_raw: Option<Vec<u8>>,
    pub uuid_source_offset: Option<u64>,
    pub uuid_source_size: u64,
    pub uuid_issues: Vec<String>,
    pub entrypoint: Option<EntryPoint>,
    pub unix_threads: Vec<UnixThread>,
    pub unix_thread_issues: Vec<String>,
    pub fileset_entries: Vec<FilesetEntry>,
    pub fileset_entry_issues: Vec<String>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dependencies: Vec<Dependency>,
    pub dylibs: Vec<DylibRecord>,
    pub dylib_issues: Vec<String>,
    pub rpaths: Vec<String>,
    pub rpath_records: Vec<PathRecord>,
    pub dyld_environment: Vec<PathRecord>,
    pub dylinkers: Vec<PathRecord>,
    pub subordinate_paths: Vec<PathRecord>,
    pub path_issues: Vec<String>,
    pub linker_options: Vec<LinkerOptionCommand>,
    pub build_metadata: Vec<BuildMetadata>,
    pub build_tools: Vec<BuildTool>,
    pub build_metadata_issues: Vec<String>,
    pub source_versions: Vec<SourceVersion>,
    pub linker_optimization_hints: Vec<LinkerOptimizationHints>,
    pub segment_split_infos: Vec<SegmentSplitInfo>,
    pub dyld_exports_tries: Vec<DyldExportsTrie>,
    pub routines: Vec<RoutinesCommand>,
    pub twolevel_hints: Vec<TwolevelHints>,
    pub twolevel_hint_issues: Vec<String>,
    pub prebound_dylibs: Vec<PreboundDylib>,
    pub imports: Vec<Symbol>,
    pub exports: Vec<Symbol>,
    pub export_records: Vec<ExportRecord>,
    pub binds: Vec<Bind>,
    pub bind_issues: Vec<String>,
    pub rebases: Vec<Rebase>,
    pub rebase_issues: Vec<String>,
    pub dyld_info: Vec<DyldInfoCommand>,
    pub chained_imports: Vec<ChainedImport>,
    pub chained_fixups: Option<ChainedFixups>,
    pub indirect_symbols: Vec<IndirectSymbol>,
    pub indirect_symbol_issues: Vec<String>,
    pub dysymtab: Option<Dysymtab>,
    pub chained_pointers: Vec<ChainedPointer>,
    pub chained_unsupported_formats: Vec<u16>,
    pub data_in_code: Vec<DataInCodeRecord>,
    pub data_in_code_tables: Vec<DataInCodeTable>,
    pub data_in_code_issues: Vec<String>,
    pub code_signatures: Vec<CodeSignature>,
    pub code_signature_commands: Vec<CodeSignatureCommand>,
    pub code_signature_children: Vec<CodeSignatureChild>,
    pub code_signature_issues: Vec<CodeSignatureIssue>,
    pub encryption_info: Vec<EncryptionInfo>,
    pub encryption_issues: Vec<String>,
    pub notes: Vec<Note>,
    pub note_issues: Vec<String>,
    pub symbol_table_count: usize,
    pub nlist_symbols: Vec<NlistSymbol>,
    pub symbol_issues: Vec<String>,
    pub load_command_count: usize,
    pub load_commands: Vec<LoadCommandRecord>,
    pub function_starts: Vec<u64>,
    pub function_start_records: Vec<FunctionStart>,
    pub function_starts_tables: Vec<FunctionStartsTable>,
    pub function_starts_issues: Vec<String>,
    #[serde(skip)]
    indirect_symbol_values: Vec<u32>,
}

/// A Mach-O slice listed by a thin image or a universal container.
#[derive(Debug, Serialize)]
pub struct ArchitectureSlice {
    pub name: String,
    pub cpu: u32,
    pub cpu_name: String,
    pub cpu_subtype: u32,
    pub cpu_subtype_name: String,
    pub file_offset: u64,
    pub size: u64,
    pub alignment: Option<u32>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct SourceVersion {
    pub raw: u64,
    pub version: String,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct FunctionStartsTable {
    pub offset: u64,
    pub size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct FunctionStart {
    pub address: u64,
    pub delta: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct LinkerOptimizationHints {
    pub offset: u64,
    pub size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct SegmentSplitInfo {
    pub offset: u64,
    pub size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct DyldExportsTrie {
    pub offset: u64,
    pub size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct RoutinesCommand {
    pub init_address: u64,
    pub term_address: u64,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct TwolevelHints {
    pub offset: u64,
    pub count: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub entries: Vec<TwolevelHint>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct TwolevelHint {
    pub raw: u32,
    pub isub_image: u8,
    pub itoc: u32,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct PreboundDylib {
    pub name: Option<String>,
    pub name_offset: u64,
    pub linked_modules_offset: u64,
    pub linked_modules_count: u64,
    pub linked_modules_valid: bool,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadCommandRecord {
    pub index: usize,
    pub command: u32,
    pub kind: String,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct Symbol {
    pub index: usize,
    pub name: String,
    pub address: u64,
    pub weak: bool,
    pub reexport: bool,
    pub source: Option<String>,
    pub source_symbol: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NlistSymbol {
    pub index: usize,
    pub string_index: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
    pub name: Option<String>,
    pub classification: Option<&'static str>,
    pub source_offset: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct ExportRecord {
    pub name: String,
    pub flags: u64,
    pub flag_names: Vec<String>,
    pub kind: &'static str,
    pub address: Option<u64>,
    pub resolver: Option<u64>,
    pub reexport_ordinal: Option<u64>,
    pub source_symbol: Option<String>,
    pub terminal_offset: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct Bind {
    pub stream: &'static str,
    pub symbol: String,
    pub ordinal: i32,
    pub library: Option<String>,
    pub bind_type: u8,
    pub segment: u8,
    pub offset: u64,
    pub addend: i64,
    pub weak_import: bool,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct Rebase {
    pub stream: &'static str,
    pub rebase_type: u8,
    pub segment: u8,
    pub offset: u64,
    pub valid: bool,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct DyldInfoRange {
    pub offset: u64,
    pub size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct DyldInfoCommand {
    pub rebase: Option<DyldInfoRange>,
    pub bind: Option<DyldInfoRange>,
    pub weak_bind: Option<DyldInfoRange>,
    pub lazy_bind: Option<DyldInfoRange>,
    pub exports: Option<DyldInfoRange>,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct ChainedImport {
    pub index: usize,
    pub symbol: String,
    pub ordinal: i32,
    pub library: Option<String>,
    pub weak: bool,
    pub addend: i64,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct ChainedFixups {
    pub data_offset: u64,
    pub data_size: u64,
    pub version: Option<u32>,
    pub starts_offset: Option<u64>,
    pub imports_offset: Option<u64>,
    pub imports_count: Option<u64>,
    pub imports_format: Option<u32>,
    pub symbols_offset: Option<u64>,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct IndirectSymbol {
    pub section: String,
    pub slot: usize,
    pub symbol_index: Option<u32>,
    pub symbol: Option<String>,
    pub source_offset: u64,
    pub raw_value: u32,
    pub classification: Option<&'static str>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct Dysymtab {
    pub indirect_symbol_offset: u64,
    pub indirect_symbol_count: u64,
    pub external_reference_offset: u64,
    pub external_reference_count: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub indirect_source_offset: u64,
    pub indirect_source_size: u64,
    pub tables: Vec<DysymtabTable>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct DysymtabTable {
    pub kind: String,
    pub offset: u64,
    pub count: u64,
    pub entry_size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct ChainedPointer {
    pub segment: usize,
    pub file_offset: u64,
    pub raw: u64,
    pub kind: &'static str,
    pub target: Option<u64>,
    pub import_index: Option<usize>,
    pub diversity: Option<u16>,
    pub address_diversity: Option<bool>,
    pub key: Option<u8>,
    pub authenticated: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DataInCodeRecord {
    pub offset: u64,
    pub length: u16,
    pub kind: u16,
    pub kind_name: String,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct DataInCodeTable {
    pub offset: u64,
    pub size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct CodeSignature {
    pub offset: u64,
    pub size: u64,
    pub valid: bool,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub flags: Option<u32>,
    pub hash_type: Option<u8>,
    pub hash_size: Option<u8>,
    pub platform: Option<u8>,
    pub signature_verification: &'static str,
    pub entitlements_offset: Option<u64>,
    pub entitlements_size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CodeSignatureCommand {
    pub blob_offset: u64,
    pub blob_size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct CodeSignatureChild {
    pub slot_type: u32,
    pub offset: u64,
    pub size: u64,
    pub magic: Option<u32>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct CodeSignatureIssue {
    pub kind: &'static str,
    pub offset: Option<u64>,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct EncryptionInfo {
    pub offset: u64,
    pub size: u64,
    pub crypt_id: u32,
    pub valid: bool,
    pub state: &'static str,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct Note {
    pub owner: String,
    pub owner_bytes: Vec<u8>,
    pub owner_utf8_valid: bool,
    pub offset: u64,
    pub size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub aligned: bool,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct EntryPoint {
    pub file_offset: u64,
    pub stack_size: u64,
    pub vm_address: Option<u64>,
    pub source_offset: u64,
    pub source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct UnixThread {
    pub flavor: u32,
    pub count: u32,
    pub state: Vec<u8>,
    pub pc: Option<u64>,
    pub supported: bool,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct FilesetEntry {
    pub entry_id: Option<String>,
    pub entry_id_bytes: Vec<u8>,
    pub entry_id_utf8_valid: bool,
    pub entry_id_source_offset: Option<u64>,
    pub entry_id_source_size: u64,
    pub source_offset: u64,
    pub source_size: u64,
    pub file_offset: Option<u64>,
    pub vm_address: Option<u64>,
    pub mapped_vm_address: Option<u64>,
    pub valid: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub raw: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Segment {
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub name_utf8_valid: bool,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub file_range_valid: bool,
    pub max_protection: u32,
    pub initial_protection: u32,
    pub maximum_permissions: Permissions,
    pub initial_permissions: Permissions,
}

#[derive(Clone, Debug, Serialize)]
pub struct Section {
    pub segment: String,
    pub segment_bytes: Vec<u8>,
    pub segment_utf8_valid: bool,
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub name_utf8_valid: bool,
    pub address: u64,
    pub size: u64,
    pub file_offset: u32,
    pub file_range_valid: bool,
    pub alignment: u32,
    pub alignment_bytes: Option<u64>,
    pub flags: u32,
    pub flag_names: Vec<String>,
    pub reserved1: u32,
    pub reserved2: u32,
}

#[derive(Debug, Serialize)]
pub struct Dependency {
    pub path: String,
    pub kind: &'static str,
    pub encoding: &'static str,
    pub weak: bool,
    pub upward: bool,
    pub reexport: bool,
    pub delayed_init: bool,
    pub current_version: Option<String>,
    pub compatibility_version: Option<String>,
    pub name_offset: Option<u64>,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct DylibRecord {
    pub kind: &'static str,
    pub encoding: &'static str,
    pub name: Option<String>,
    pub name_bytes: Vec<u8>,
    pub name_utf8_valid: bool,
    pub name_offset: Option<u64>,
    pub name_source_offset: Option<u64>,
    pub name_source_size: u64,
    pub timestamp: Option<u32>,
    pub weak: bool,
    pub upward: bool,
    pub reexport: bool,
    pub delayed_init: bool,
    pub current_version: Option<String>,
    pub compatibility_version: Option<String>,
    pub command_offset: u64,
    pub command_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct PathRecord {
    pub value: Option<String>,
    pub raw_bytes: Vec<u8>,
    pub utf8_valid: bool,
    pub command_offset: u64,
    pub command_size: u64,
    pub string_offset: Option<u64>,
    pub string_source_offset: Option<u64>,
    pub string_source_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct LinkerOptionCommand {
    pub declared_count: u32,
    pub options: Vec<String>,
    pub raw_options: Vec<Vec<u8>>,
    pub option_records: Vec<LinkerOptionRecord>,
    pub command_offset: u64,
    pub command_size: u64,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct LinkerOptionRecord {
    pub value: Option<String>,
    pub raw_bytes: Vec<u8>,
    pub source_offset: u64,
    pub source_size: u64,
    pub terminated: bool,
    pub utf8_valid: bool,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct BuildMetadata {
    pub command_kind: &'static str,
    pub platform: Option<u32>,
    pub platform_name: Option<String>,
    pub min_os: Option<String>,
    pub min_os_raw: Option<u32>,
    pub sdk: Option<String>,
    pub sdk_raw: Option<u32>,
    pub tool: Option<String>,
    pub source_offset: u64,
    pub source_size: u64,
}

#[derive(Debug, Serialize)]
pub struct BuildTool {
    pub tool: u32,
    pub tool_name: String,
    pub version: String,
    pub version_raw: u32,
    pub source_offset: u64,
    pub source_size: u64,
}

/// Lists architecture slices without selecting or parsing a slice.
pub fn architectures(bytes: &[u8]) -> Result<Vec<ArchitectureSlice>, Error> {
    let magic = read_be(bytes, 0)?;

    if matches!(magic, 0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe) {
        let little = matches!(magic, 0xcefaedfe | 0xcffaedfe);
        let cpu = read_u32(bytes, 4, little)?;
        let cpu_subtype = read_u32(bytes, 8, little)?;
        return Ok(vec![ArchitectureSlice {
            name: cpu_name(cpu).to_owned(),
            cpu,
            cpu_name: cpu_name(cpu).to_owned(),
            cpu_subtype,
            cpu_subtype_name: cpu_subtype_name(cpu, cpu_subtype),
            file_offset: 0,
            size: bytes.len() as u64,
            alignment: None,
            valid: true,
        }]);
    }

    let (little, is_64_bit) = match magic {
        0xcafebabe => (false, false),
        0xbebafeca => (true, false),
        0xcafebabf => (false, true),
        0xbfbafeca => (true, true),
        _ => return Err(Error::Unsupported("Input is not a Mach-O image")),
    };
    let count = read_u32(bytes, 4, little)? as usize;
    if count > MAX_ARCHITECTURES {
        return Err(Error::Unsupported("Universal Mach-O has too many slices"));
    }

    let entry_size = if is_64_bit { 32 } else { 20 };
    let table_end = 8usize
        .checked_add(count.checked_mul(entry_size).ok_or(Error::Malformed(
            "Universal Mach-O architecture table overflows",
        ))?)
        .ok_or(Error::Malformed(
            "Universal Mach-O architecture table overflows",
        ))?;
    if table_end > bytes.len() {
        return Err(Error::Malformed(
            "Universal Mach-O architecture table is truncated",
        ));
    }

    let mut slices = Vec::with_capacity(count);
    for index in 0..count {
        let entry = 8 + index * entry_size;
        let cpu = read_u32(bytes, entry, little)?;
        let cpu_subtype = read_u32(bytes, entry + 4, little)?;
        let (file_offset, size, alignment) = if is_64_bit {
            (
                read_u64(bytes, entry + 8, little)?,
                read_u64(bytes, entry + 16, little)?,
                read_u32(bytes, entry + 24, little)?,
            )
        } else {
            (
                read_u32(bytes, entry + 8, little)? as u64,
                read_u32(bytes, entry + 12, little)? as u64,
                read_u32(bytes, entry + 16, little)?,
            )
        };
        let valid = file_offset
            .checked_add(size)
            .is_some_and(|end| end <= bytes.len() as u64);
        slices.push(ArchitectureSlice {
            name: cpu_name(cpu).to_owned(),
            cpu,
            cpu_name: cpu_name(cpu).to_owned(),
            cpu_subtype,
            cpu_subtype_name: cpu_subtype_name(cpu, cpu_subtype),
            file_offset,
            size,
            alignment: Some(alignment),
            valid,
        });
    }
    Ok(slices)
}

pub fn read(bytes: &[u8]) -> Result<Image, Error> {
    let magic = read_be(bytes, 0)?;
    let (little, bits) = match magic {
        0xfeedface => (false, 32),
        0xcefaedfe => (true, 32),
        0xfeedfacf => (false, 64),
        0xcffaedfe => (true, 64),
        0xcafebabe | 0xcafebabf | 0xbebafeca | 0xbfbafeca => {
            return Err(Error::Unsupported(
                "Universal Mach-O requires an explicit architecture selection",
            ));
        }
        _ => return Err(Error::Unsupported("Input is not a Mach-O image")),
    };
    let header_size: usize = if bits == 64 { 32 } else { 28 };
    let cpu = read_u32(bytes, 4, little)?;
    let cpu_subtype = read_u32(bytes, 8, little)?;
    let file_type = read_u32(bytes, 12, little)?;
    let header_flags = read_u32(bytes, 24, little)?;
    let command_count = read_u32(bytes, 16, little)? as usize;
    let command_bytes = read_u32(bytes, 20, little)? as usize;
    if command_bytes > MAX_COMMAND_BYTES {
        return Err(Error::Unsupported(
            "Mach-O load commands exceed the 16 MiB limit",
        ));
    }
    let command_end = header_size
        .checked_add(command_bytes)
        .ok_or(Error::Malformed("Mach-O load command range overflowed"))?;
    if command_end > bytes.len() {
        return Err(Error::Malformed("Mach-O load commands are truncated"));
    }

    let mut image = Image {
        word_size: bits,
        endian: if little { "little" } else { "big" },
        cpu,
        cpu_name: cpu_name(cpu).to_owned(),
        cpu_subtype,
        cpu_subtype_name: cpu_subtype_name(cpu, cpu_subtype).to_owned(),
        file_type,
        file_type_name: file_type_name(file_type).to_owned(),
        flags: header_flags,
        flag_names: header_flag_names(header_flags),
        uuid: None,
        uuid_raw: None,
        uuid_source_offset: None,
        uuid_source_size: 0,
        uuid_issues: Vec::new(),
        entrypoint: None,
        unix_threads: Vec::new(),
        unix_thread_issues: Vec::new(),
        fileset_entries: Vec::new(),
        fileset_entry_issues: Vec::new(),
        segments: Vec::new(),
        sections: Vec::new(),
        dependencies: Vec::new(),
        dylibs: Vec::new(),
        dylib_issues: Vec::new(),
        rpaths: Vec::new(),
        rpath_records: Vec::new(),
        dyld_environment: Vec::new(),
        dylinkers: Vec::new(),
        subordinate_paths: Vec::new(),
        path_issues: Vec::new(),
        linker_options: Vec::new(),
        build_metadata: Vec::new(),
        build_tools: Vec::new(),
        build_metadata_issues: Vec::new(),
        source_versions: Vec::new(),
        linker_optimization_hints: Vec::new(),
        segment_split_infos: Vec::new(),
        dyld_exports_tries: Vec::new(),
        routines: Vec::new(),
        twolevel_hints: Vec::new(),
        twolevel_hint_issues: Vec::new(),
        prebound_dylibs: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        export_records: Vec::new(),
        binds: Vec::new(),
        bind_issues: Vec::new(),
        rebases: Vec::new(),
        rebase_issues: Vec::new(),
        dyld_info: Vec::new(),
        chained_imports: Vec::new(),
        chained_fixups: None,
        indirect_symbols: Vec::new(),
        indirect_symbol_issues: Vec::new(),
        dysymtab: None,
        chained_pointers: Vec::new(),
        chained_unsupported_formats: Vec::new(),
        data_in_code: Vec::new(),
        data_in_code_tables: Vec::new(),
        data_in_code_issues: Vec::new(),
        code_signatures: Vec::new(),
        code_signature_commands: Vec::new(),
        code_signature_children: Vec::new(),
        code_signature_issues: Vec::new(),
        encryption_info: Vec::new(),
        encryption_issues: Vec::new(),
        notes: Vec::new(),
        note_issues: Vec::new(),
        symbol_table_count: 0,
        nlist_symbols: Vec::new(),
        symbol_issues: Vec::new(),
        load_command_count: command_count,
        load_commands: Vec::new(),
        function_starts: Vec::new(),
        function_start_records: Vec::new(),
        function_starts_tables: Vec::new(),
        function_starts_issues: Vec::new(),
        indirect_symbol_values: Vec::new(),
    };
    let mut offset = header_size;
    // Mach-O load commands are 4-byte aligned in 32-bit images and 8-byte
    // aligned in 64-bit images.  Keep this structural rule at the command
    // boundary so a command that happens to fit the byte budget cannot shift
    // every following command onto an invalid boundary.
    let command_alignment = if bits == 64 { 8 } else { 4 };
    for index in 0..command_count {
        let command = read_u32(bytes, offset, little)?;
        let size = read_u32(bytes, offset + 4, little)? as usize;
        if size < 8 || !size.is_multiple_of(command_alignment) || offset + size > command_end {
            return Err(Error::Malformed("Invalid Mach-O load command"));
        }
        image.load_commands.push(LoadCommandRecord {
            index,
            command,
            kind: command_name(command).to_owned(),
            source_offset: offset as u64,
            source_size: size as u64,
            valid: true,
        });
        parse_command(bytes, offset, size, command, bits, little, &mut image)?;
        offset += size;
    }
    if offset != command_end {
        return Err(Error::Malformed(
            "Mach-O load command count disagrees with command bytes",
        ));
    }
    resolve_ordinals(&mut image);
    resolve_indirect_symbols(&mut image);
    finalize_entrypoint(&bytes, &mut image);
    finalize_fileset_entries(&bytes, &mut image);
    Ok(image)
}

fn parse_command(
    bytes: &[u8],
    offset: usize,
    size: usize,
    command: u32,
    bits: u8,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    match command {
        0x1 | 0x19 => parse_segment(bytes, offset, size, command == 0x19, little, image),
        0x2 => parse_symbol_table(bytes, offset, size, bits, little, image),
        0xb => parse_dysymtab(bytes, offset, size, little, image),
        0x22 | 0x8000_0022 => parse_dyld_info(bytes, offset, size, little, image),
        0x8000_0034 => parse_chained_fixups(bytes, offset, size, little, image),
        0x26 => parse_function_starts(bytes, offset, size, little, image),
        0x29 => parse_data_in_code(bytes, offset, size, little, image),
        0x1d => parse_code_signature(bytes, offset, size, little, image),
        0x21 | 0x2c => parse_encryption_info(bytes, offset, size, command, little, image),
        0x31 => parse_note(bytes, offset, size, little, image),
        0x8000_0035 => parse_fileset_entry(bytes, offset, size, little, image),
        0x1b => {
            if size < 20 {
                return Err(Error::Malformed("Truncated LC_UUID command"));
            }
            let raw = &bytes[offset + 8..offset + 24];
            if let Some(previous) = image.uuid_raw.as_deref() {
                if previous != raw {
                    image.uuid = None;
                    image.uuid_raw = None;
                    image.uuid_source_offset = None;
                    image.uuid_source_size = 0;
                    image
                        .uuid_issues
                        .push("Conflicting LC_UUID commands make the image UUID unknown".into());
                }
            } else if image.uuid_issues.is_empty() {
                image.uuid = Some(format_uuid(raw));
                image.uuid_raw = Some(raw.to_vec());
                image.uuid_source_offset = Some(offset as u64);
                image.uuid_source_size = size as u64;
            }
            Ok(())
        }
        0xc | 0xd | 0x20 | 0x8000_0018 | 0x8000_001f | 0x8000_0023 => {
            let kind = match command {
                0xc => "load",
                0x8000_0018 => "weak",
                0x8000_001f => "reexport",
                0x20 => "lazy",
                0xd => "id",
                _ => "upward",
            };
            let record = parse_dylib(bytes, offset, size, little, kind, image);
            if let Some(path) = record.name.clone() {
                image.dependencies.push(Dependency {
                    path,
                    kind,
                    encoding: record.encoding,
                    weak: record.weak,
                    upward: record.upward,
                    reexport: record.reexport,
                    delayed_init: record.delayed_init,
                    current_version: record.current_version.clone(),
                    compatibility_version: record.compatibility_version.clone(),
                    name_offset: record.name_offset,
                    source_offset: record.command_offset,
                    source_size: record.command_size,
                });
            }
            image.dylibs.push(record);
            Ok(())
        }
        0x8000_001c => {
            let record = parse_path_record(bytes, offset, size, 8, little, image);
            if let Some(value) = record.value.clone() {
                image.rpaths.push(value);
            }
            image.rpath_records.push(record);
            Ok(())
        }
        0x27 => {
            let record = parse_path_record(bytes, offset, size, 8, little, image);
            image.dyld_environment.push(record);
            Ok(())
        }
        0xe | 0xf => {
            let record = parse_path_record(bytes, offset, size, 8, little, image);
            image.dylinkers.push(record);
            Ok(())
        }
        0x12 | 0x13 | 0x14 | 0x15 => {
            let record = parse_path_record(bytes, offset, size, 8, little, image);
            image.subordinate_paths.push(record);
            Ok(())
        }
        0x2d => parse_linker_option(bytes, offset, size, little, image),
        0x2a => {
            if size < 16 {
                return Err(Error::Malformed("Truncated LC_SOURCE_VERSION command"));
            }
            image.source_versions.push(SourceVersion {
                raw: read_u64(bytes, offset + 8, little)?,
                version: source_version(read_u64(bytes, offset + 8, little)?),
                source_offset: offset as u64,
                source_size: size as u64,
                valid: true,
            });
            Ok(())
        }
        0x1e => {
            if size < 16 {
                return Err(Error::Malformed("Truncated LC_SEGMENT_SPLIT_INFO command"));
            }
            let data_offset = read_u32(bytes, offset + 8, little)? as u64;
            let data_size = read_u32(bytes, offset + 12, little)? as u64;
            let valid = data_size <= MAX_COMMAND_BYTES as u64
                && data_offset
                    .checked_add(data_size)
                    .is_some_and(|end| end <= bytes.len() as u64);
            image.segment_split_infos.push(SegmentSplitInfo {
                offset: data_offset,
                size: data_size,
                source_offset: offset as u64,
                source_size: size as u64,
                valid,
            });
            Ok(())
        }
        0x2e => {
            if size < 16 {
                return Err(Error::Malformed(
                    "Truncated LC_LINKER_OPTIMIZATION_HINTS command",
                ));
            }
            let data_offset = read_u32(bytes, offset + 8, little)? as u64;
            let data_size = read_u32(bytes, offset + 12, little)? as u64;
            let valid = data_size <= MAX_COMMAND_BYTES as u64
                && data_offset
                    .checked_add(data_size)
                    .is_some_and(|end| end <= bytes.len() as u64);
            image
                .linker_optimization_hints
                .push(LinkerOptimizationHints {
                    offset: data_offset,
                    size: data_size,
                    source_offset: offset as u64,
                    source_size: size as u64,
                    valid,
                });
            Ok(())
        }
        0x8000_0033 => {
            if size < 16 {
                return Err(Error::Malformed("Truncated LC_DYLD_EXPORTS_TRIE command"));
            }
            let data_offset = read_u32(bytes, offset + 8, little)? as u64;
            let data_size = read_u32(bytes, offset + 12, little)? as u64;
            let valid = data_offset
                .checked_add(data_size)
                .is_some_and(|end| end <= bytes.len() as u64);
            image.dyld_exports_tries.push(DyldExportsTrie {
                offset: data_offset,
                size: data_size,
                source_offset: offset as u64,
                source_size: size as u64,
                valid,
            });
            if data_size != 0 {
                parse_export_trie(bytes, data_offset as usize, data_size as usize, image)?;
            }
            Ok(())
        }
        0x11 | 0x8000_001a => {
            let required = if command == 0x11 { 40 } else { 72 };
            if size < required {
                return Err(Error::Malformed("Truncated LC_ROUTINES command"));
            }
            let wide = command == 0x8000_001a;
            image.routines.push(RoutinesCommand {
                init_address: word(bytes, offset + 8, wide, little)?,
                term_address: word(bytes, offset + if wide { 16 } else { 12 }, wide, little)?,
                source_offset: offset as u64,
                source_size: size as u64,
            });
            Ok(())
        }
        0x16 => {
            if size < 16 {
                return Err(Error::Malformed("Truncated LC_TWOLEVEL_HINTS command"));
            }
            let data_offset = read_u32(bytes, offset + 8, little)? as u64;
            let count = read_u32(bytes, offset + 12, little)? as u64;
            let byte_size = count.checked_mul(4);
            let valid = count <= MAX_SYMBOLS as u64
                && byte_size
                    .and_then(|length| data_offset.checked_add(length))
                    .is_some_and(|end| end <= bytes.len() as u64);
            let mut entries = Vec::new();
            if valid {
                let start = data_offset as usize;
                for index in 0..count as usize {
                    let source_offset = start + index * 4;
                    let raw = read_u32(bytes, source_offset, little)?;
                    entries.push(TwolevelHint {
                        raw,
                        isub_image: (raw & 0xff) as u8,
                        itoc: raw >> 8,
                        source_offset: source_offset as u64,
                        source_size: 4,
                        valid: true,
                    });
                }
            } else {
                image
                    .twolevel_hint_issues
                    .push("LC_TWOLEVEL_HINTS table is malformed or out of file".into());
            }
            image.twolevel_hints.push(TwolevelHints {
                offset: data_offset,
                count,
                source_offset: offset as u64,
                source_size: size as u64,
                entries,
                valid,
            });
            Ok(())
        }
        0x10 => {
            if size < 24 {
                return Err(Error::Malformed("Truncated LC_PREBOUND_DYLIB command"));
            }
            let name_offset = read_u32(bytes, offset + 8, little)? as u64;
            let linked_modules_count = read_u32(bytes, offset + 12, little)? as u64;
            let linked_modules_offset = read_u32(bytes, offset + 16, little)? as u64;
            let name = bounded_string(bytes, offset, size, name_offset as usize);
            let linked_modules_valid = linked_modules_offset
                .checked_add(linked_modules_count)
                .is_some_and(|end| end <= bytes.len() as u64);
            let valid = name.is_some() && linked_modules_valid;
            image.prebound_dylibs.push(PreboundDylib {
                name,
                name_offset,
                linked_modules_offset,
                linked_modules_count,
                linked_modules_valid,
                source_offset: offset as u64,
                source_size: size as u64,
                valid,
            });
            Ok(())
        }
        0x8000_0028 => {
            if size < 24 {
                return Err(Error::Malformed("Truncated LC_MAIN command"));
            }
            image.entrypoint = Some(EntryPoint {
                file_offset: read_u64(bytes, offset + 8, little)?,
                stack_size: read_u64(bytes, offset + 16, little)?,
                vm_address: None,
                source_offset: offset as u64,
                source_size: size as u64,
                valid: true,
            });
            Ok(())
        }
        0x32 => {
            if size < 24 {
                return Err(Error::Malformed("Truncated LC_BUILD_VERSION command"));
            }
            image.build_metadata.push(BuildMetadata {
                command_kind: "LC_BUILD_VERSION",
                platform: Some(read_u32(bytes, offset + 8, little)?),
                platform_name: Some(platform_name(read_u32(bytes, offset + 8, little)?)),
                min_os: Some(version(read_u32(bytes, offset + 12, little)?)),
                min_os_raw: Some(read_u32(bytes, offset + 12, little)?),
                sdk: Some(version(read_u32(bytes, offset + 16, little)?)),
                sdk_raw: Some(read_u32(bytes, offset + 16, little)?),
                tool: None,
                source_offset: offset as u64,
                source_size: size as u64,
            });
            let declared_tools = read_u32(bytes, offset + 20, little)? as usize;
            let available_tools = (size - 24) / 8;
            let tool_count = declared_tools.min(available_tools);
            if declared_tools > available_tools {
                image.build_metadata_issues.push(format!(
                    "LC_BUILD_VERSION declares {declared_tools} tools but only {available_tools} fit"
                ));
            }
            for index in 0..tool_count {
                let tool_offset = offset + 24 + index * 8;
                let version_raw = read_u32(bytes, tool_offset + 4, little)?;
                image.build_tools.push(BuildTool {
                    tool: read_u32(bytes, tool_offset, little)?,
                    tool_name: tool_name(read_u32(bytes, tool_offset, little)?),
                    version: version(version_raw),
                    version_raw,
                    source_offset: tool_offset as u64,
                    source_size: 8,
                });
            }
            Ok(())
        }
        0x24 | 0x25 | 0x2f | 0x30 => {
            if size < 16 {
                return Err(Error::Malformed("Truncated minimum OS command"));
            }
            let platform = minimum_os_platform(command, image.cpu);
            image.build_metadata.push(BuildMetadata {
                command_kind: minimum_os_command_name(command),
                platform: Some(platform),
                platform_name: Some(minimum_os_platform_name(command, platform).to_owned()),
                min_os: Some(version(read_u32(bytes, offset + 8, little)?)),
                min_os_raw: Some(read_u32(bytes, offset + 8, little)?),
                sdk: Some(version(read_u32(bytes, offset + 12, little)?)),
                sdk_raw: Some(read_u32(bytes, offset + 12, little)?),
                tool: None,
                source_offset: offset as u64,
                source_size: size as u64,
            });
            Ok(())
        }
        0x4 | 0x5 => parse_unixthread(bytes, offset, size, little, image),
        _ => {
            let _ = bits;
            Ok(())
        }
    }
}

fn finalize_entrypoint(bytes: &[u8], image: &mut Image) {
    let Some(entrypoint) = image.entrypoint.as_mut() else {
        return;
    };

    entrypoint.valid = entrypoint
        .file_offset
        .checked_add(1)
        .is_some_and(|end| end <= bytes.len() as u64);
    if !entrypoint.valid {
        return;
    }

    let Some(segment) = image.segments.iter().find(|segment| {
        entrypoint.file_offset >= segment.file_offset
            && entrypoint.file_offset - segment.file_offset < segment.file_size
    }) else {
        return;
    };
    let delta = entrypoint.file_offset - segment.file_offset;
    entrypoint.vm_address = segment.vm_address.checked_add(delta);
}

fn finalize_fileset_entries(bytes: &[u8], image: &mut Image) {
    for entry in &mut image.fileset_entries {
        let Some(file_offset) = entry.file_offset else {
            continue;
        };
        entry.valid = file_offset < bytes.len() as u64;
        if !entry.valid {
            continue;
        }
        let Some(segment) = image.segments.iter().find(|segment| {
            file_offset >= segment.file_offset
                && file_offset - segment.file_offset < segment.file_size
        }) else {
            continue;
        };
        let delta = file_offset - segment.file_offset;
        entry.mapped_vm_address = segment.vm_address.checked_add(delta);
    }
}

fn parse_fileset_entry(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 32 {
        image
            .fileset_entry_issues
            .push("Truncated LC_FILESET_ENTRY command".into());
        image.fileset_entries.push(FilesetEntry {
            entry_id: None,
            entry_id_bytes: Vec::new(),
            entry_id_utf8_valid: false,
            entry_id_source_offset: None,
            entry_id_source_size: 0,
            source_offset: command as u64,
            source_size: command_size as u64,
            file_offset: None,
            vm_address: None,
            mapped_vm_address: None,
            valid: false,
        });
        return Ok(());
    }

    let vm_address = read_u64(bytes, command + 8, little)?;
    let file_offset = read_u64(bytes, command + 16, little)?;
    let entry_id_offset = read_u32(bytes, command + 24, little)? as usize;
    let mut entry_id_source_offset = None;
    let mut entry_id_source_size = 0;
    let entry_id_bytes = if entry_id_offset < command_size {
        let start = command
            .checked_add(entry_id_offset)
            .ok_or(Error::Malformed("LC_FILESET_ENTRY ID offset overflowed"))?;
        let end = command.checked_add(command_size).ok_or(Error::Malformed(
            "LC_FILESET_ENTRY command range overflowed",
        ))?;
        let raw = bytes.get(start..end).ok_or(Error::Malformed(
            "LC_FILESET_ENTRY ID is outside the command",
        ))?;
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        entry_id_source_offset = Some(start as u64);
        entry_id_source_size = end as u64;
        raw[..end].to_vec()
    } else {
        image
            .fileset_entry_issues
            .push("LC_FILESET_ENTRY ID offset is outside the command".into());
        Vec::new()
    };
    let entry_id_utf8_valid = std::str::from_utf8(&entry_id_bytes).is_ok();
    if !entry_id_utf8_valid {
        image
            .fileset_entry_issues
            .push("LC_FILESET_ENTRY ID is not valid UTF-8".into());
    }
    let entry_id = if entry_id_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&entry_id_bytes).into_owned())
    };
    image.fileset_entries.push(FilesetEntry {
        entry_id,
        entry_id_bytes,
        entry_id_utf8_valid,
        entry_id_source_offset,
        entry_id_source_size,
        source_offset: command as u64,
        source_size: command_size as u64,
        file_offset: Some(file_offset),
        vm_address: Some(vm_address),
        mapped_vm_address: None,
        valid: false,
    });
    Ok(())
}

fn parse_unixthread(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 16 {
        return Err(Error::Malformed("Truncated LC_UNIXTHREAD command"));
    }
    let flavor = read_u32(bytes, command + 8, little)?;
    let count = read_u32(bytes, command + 12, little)?;
    let state = bytes
        .get(command + 16..command + command_size)
        .ok_or(Error::Malformed("Truncated LC_UNIXTHREAD state"))?
        .to_vec();
    let (pc_offset, expected_state_size, supported) = match (image.cpu, flavor) {
        (0x0100_0007, 4) => (16 * 8, 21 * 8, true),
        (0x0100_000c, 6) => (32 * 8, 34 * 8, true),
        _ => (0, 0, false),
    };
    let valid = if supported {
        count as usize * 4 >= expected_state_size && state.len() >= expected_state_size
    } else {
        true
    };
    let pc = if supported && valid {
        Some(read_u64(&state, pc_offset, little)?)
    } else {
        None
    };
    if supported && !valid {
        image
            .unix_thread_issues
            .push("LC_UNIXTHREAD register state is truncated".into());
    }
    image.unix_threads.push(UnixThread {
        flavor,
        count,
        state,
        pc,
        supported,
        valid,
    });
    Ok(())
}

fn parse_segment(
    bytes: &[u8],
    offset: usize,
    size: usize,
    wide: bool,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    let header = if wide { 72 } else { 56 };
    let section_width = if wide { 80 } else { 68 };
    if size < header {
        return Err(Error::Malformed("Truncated Mach-O segment command"));
    }
    let (name, name_bytes, name_utf8_valid) = fixed_name_record(bytes, offset + 8, 16)?;
    let max_protection = read_u32(bytes, offset + if wide { 56 } else { 40 }, little)?;
    let initial_protection = read_u32(bytes, offset + if wide { 60 } else { 44 }, little)?;
    let segment = Segment {
        name: name.clone(),
        name_bytes,
        name_utf8_valid,
        vm_address: word(bytes, offset + 24, wide, little)?,
        vm_size: word(bytes, offset + if wide { 32 } else { 28 }, wide, little)?,
        file_offset: word(bytes, offset + if wide { 40 } else { 32 }, wide, little)?,
        file_size: word(bytes, offset + if wide { 48 } else { 36 }, wide, little)?,
        max_protection,
        initial_protection,
        maximum_permissions: permissions(max_protection),
        initial_permissions: permissions(initial_protection),
        file_range_valid: false,
    };
    let mut segment = segment;
    segment.file_range_valid = segment
        .file_offset
        .checked_add(segment.file_size)
        .is_some_and(|end| end <= bytes.len() as u64);
    let count = read_u32(bytes, offset + if wide { 64 } else { 48 }, little)? as usize;
    if count > (size - header) / section_width {
        return Err(Error::Malformed("Mach-O sections exceed segment command"));
    }
    image.segments.push(segment);
    for index in 0..count {
        let section = offset + header + index * section_width;
        let flags = read_u32(bytes, section + if wide { 64 } else { 56 }, little)?;
        let file_offset = read_u32(bytes, section + if wide { 48 } else { 40 }, little)?;
        let section_size = word(bytes, section + if wide { 40 } else { 36 }, wide, little)?;
        let (section_name, section_name_bytes, section_name_utf8_valid) =
            fixed_name_record(bytes, section, 16)?;
        let (segment_name, segment_name_bytes, segment_name_utf8_valid) =
            fixed_name_record(bytes, section + 16, 16)?;
        image.sections.push(Section {
            name: section_name,
            name_bytes: section_name_bytes,
            name_utf8_valid: section_name_utf8_valid,
            segment: segment_name,
            segment_bytes: segment_name_bytes,
            segment_utf8_valid: segment_name_utf8_valid,
            address: word(bytes, section + 32, wide, little)?,
            size: section_size,
            file_offset,
            file_range_valid: (file_offset as u64)
                .checked_add(section_size)
                .is_some_and(|end| end <= bytes.len() as u64),
            alignment: read_u32(bytes, section + if wide { 52 } else { 44 }, little)?,
            alignment_bytes: {
                let exponent = read_u32(bytes, section + if wide { 52 } else { 44 }, little)?;
                (exponent <= 52).then(|| 1u64 << exponent)
            },
            flags,
            flag_names: section_flag_names(flags),
            reserved1: read_u32(bytes, section + if wide { 68 } else { 60 }, little)?,
            reserved2: read_u32(bytes, section + if wide { 72 } else { 64 }, little)?,
        });
    }
    Ok(())
}

fn parse_symbol_table(
    bytes: &[u8],
    offset: usize,
    size: usize,
    bits: u8,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if size < 24 {
        return Err(Error::Malformed("Truncated LC_SYMTAB command"));
    }
    let symbol_offset = read_u32(bytes, offset + 8, little)? as usize;
    let symbol_count = read_u32(bytes, offset + 12, little)? as usize;
    let string_offset = read_u32(bytes, offset + 16, little)? as usize;
    let string_size = read_u32(bytes, offset + 20, little)? as usize;
    if symbol_count > MAX_SYMBOLS {
        return Err(Error::Unsupported(
            "Mach-O symbol table exceeds the symbol limit",
        ));
    }
    let entry_size = if bits == 64 { 16 } else { 12 };
    let symbol_bytes = symbol_count
        .checked_mul(entry_size)
        .ok_or(Error::Malformed("Mach-O symbol table range overflowed"))?;
    let symbol_end = symbol_offset
        .checked_add(symbol_bytes)
        .ok_or(Error::Malformed("Mach-O symbol table range overflowed"))?;
    let string_end = string_offset
        .checked_add(string_size)
        .ok_or(Error::Malformed("Mach-O string table range overflowed"))?;
    if symbol_end > bytes.len() || string_end > bytes.len() {
        return Err(Error::Malformed(
            "Mach-O symbol or string table is truncated",
        ));
    }
    image.symbol_table_count = symbol_count;
    let strings = &bytes[string_offset..string_end];
    for index in 0..symbol_count {
        let entry = symbol_offset + index * entry_size;
        let string_index = read_u32(bytes, entry, little)? as usize;
        let n_type = bytes[entry + 4];
        let n_sect = bytes[entry + 5];
        let n_desc = read_u16(bytes, entry + 6, little)?;
        let n_value = if bits == 64 {
            read_u64(bytes, entry + 8, little)?
        } else {
            u64::from(read_u32(bytes, entry + 8, little)?)
        };
        let classification = match n_type & 0x0e {
            0x00 => Some("undefined"),
            0x02 => Some("absolute"),
            0x0e => Some("section"),
            0x0c => Some("prebound-undefined"),
            _ => None,
        };
        let mut valid = true;
        let name = if string_index >= strings.len() {
            valid = false;
            image.symbol_issues.push(format!(
                "Symbol {index} string index {string_index} is outside the string table"
            ));
            None
        } else {
            let name_bytes = &strings[string_index..];
            let name_end = name_bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name_bytes.len());
            Some(String::from_utf8_lossy(&name_bytes[..name_end]).into_owned())
        };
        image.nlist_symbols.push(NlistSymbol {
            index,
            string_index: string_index as u32,
            n_type,
            n_sect,
            n_desc,
            n_value,
            name: name.clone(),
            classification,
            source_offset: entry as u64,
            valid,
        });
        if !valid {
            continue;
        }
        let Some(name) = name else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        const N_EXT: u8 = 0x01;
        const N_UNDF: u8 = 0x00;
        if n_type & N_EXT == 0 {
            continue;
        }
        let symbol = Symbol {
            index,
            name,
            address: n_value,
            weak: n_desc & 0x00c0 != 0,
            reexport: false,
            source: None,
            source_symbol: None,
        };
        if n_type & 0x0e == N_UNDF {
            image.imports.push(symbol);
        } else {
            image.exports.push(symbol);
        }
    }
    Ok(())
}

fn parse_dysymtab(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 80 {
        return Err(Error::Malformed("Truncated LC_DYSYMTAB command"));
    }
    let external_reference_offset = read_u32(bytes, command + 48, little)? as u64;
    let external_reference_count = read_u32(bytes, command + 52, little)? as u64;
    let offset = read_u32(bytes, command + 56, little)? as usize;
    let count = read_u32(bytes, command + 60, little)? as usize;
    let descriptors = [
        (
            "toc",
            read_u32(bytes, command + 32, little)? as u64,
            read_u32(bytes, command + 36, little)? as u64,
            8u64,
        ),
        (
            "module",
            read_u32(bytes, command + 40, little)? as u64,
            read_u32(bytes, command + 44, little)? as u64,
            if image.word_size == 64 { 56 } else { 52 },
        ),
        (
            "external_references",
            external_reference_offset,
            external_reference_count,
            4,
        ),
        ("indirect_symbols", offset as u64, count as u64, 4),
        (
            "external_relocations",
            read_u32(bytes, command + 64, little)? as u64,
            read_u32(bytes, command + 68, little)? as u64,
            8,
        ),
        (
            "local_relocations",
            read_u32(bytes, command + 72, little)? as u64,
            read_u32(bytes, command + 76, little)? as u64,
            8,
        ),
    ];
    let mut tables = Vec::with_capacity(descriptors.len());
    let mut tables_valid = true;
    for (kind, table_offset, table_count, entry_size) in descriptors {
        let byte_size = table_count.checked_mul(entry_size);
        let end = byte_size.and_then(|size| table_offset.checked_add(size));
        let valid = table_count == 0
            || (table_count <= MAX_SYMBOLS as u64
                && byte_size.is_some_and(|size| size <= MAX_COMMAND_BYTES as u64)
                && end.is_some_and(|end| end <= bytes.len() as u64));
        if !valid {
            tables_valid = false;
            image
                .indirect_symbol_issues
                .push(format!("Dysymtab {kind} table is malformed or out of file"));
        }
        tables.push(DysymtabTable {
            kind: kind.to_owned(),
            offset: table_offset,
            count: table_count,
            entry_size,
            source_offset: table_offset,
            source_size: byte_size.unwrap_or(0),
            valid,
        });
    }
    image.dysymtab = Some(Dysymtab {
        indirect_symbol_offset: offset as u64,
        indirect_symbol_count: count as u64,
        external_reference_offset,
        external_reference_count,
        source_offset: command as u64,
        source_size: command_size as u64,
        indirect_source_offset: offset as u64,
        indirect_source_size: (count as u64).checked_mul(4).unwrap_or(u64::MAX),
        tables,
        valid: tables_valid,
    });
    if count > MAX_SYMBOLS {
        if let Some(dysymtab) = image.dysymtab.as_mut() {
            dysymtab.valid = false;
        }
        image
            .indirect_symbol_issues
            .push("Indirect symbol table exceeds the symbol limit".into());
        return Ok(());
    }
    let Some(end) = offset.checked_add(count.saturating_mul(4)) else {
        if let Some(dysymtab) = image.dysymtab.as_mut() {
            dysymtab.valid = false;
        }
        image
            .indirect_symbol_issues
            .push("Indirect symbol table range overflowed".into());
        return Ok(());
    };
    if end > bytes.len() {
        if let Some(dysymtab) = image.dysymtab.as_mut() {
            dysymtab.valid = false;
        }
        image
            .indirect_symbol_issues
            .push("Indirect symbol table is truncated".into());
        return Ok(());
    }
    for index in 0..count {
        image
            .indirect_symbol_values
            .push(read_u32(bytes, offset + index * 4, little)?);
    }
    Ok(())
}

fn resolve_indirect_symbols(image: &mut Image) {
    const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
    const S_SYMBOL_STUBS: u32 = 0x8;
    const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
    const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
    const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
    const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
    let pointer_width = u64::from(image.word_size / 8);
    let values = image.indirect_symbol_values.clone();

    let sections = image.sections.clone();
    for section in &sections {
        let section_type = section.flags & 0xff;
        let is_indirect = matches!(
            section_type,
            S_LAZY_SYMBOL_POINTERS
                | S_SYMBOL_STUBS
                | S_NON_LAZY_SYMBOL_POINTERS
                | S_LAZY_DYLIB_SYMBOL_POINTERS
        );
        if !is_indirect {
            continue;
        }
        let stride = if section_type == S_SYMBOL_STUBS {
            u64::from(section.reserved2)
        } else {
            pointer_width
        };
        if stride == 0 {
            image.indirect_symbol_issues.push(format!(
                "Indirect section {} has zero slot width",
                section.name
            ));
            continue;
        }
        let slots = section.size / stride;
        let start = u64::from(section.reserved1);
        for slot in 0..slots {
            let table_index = start.saturating_add(slot);
            let Some(raw) = values.get(table_index as usize).copied() else {
                image.indirect_symbol_issues.push(format!(
                    "Indirect section {} references table entry {} outside the table",
                    section.name, table_index
                ));
                continue;
            };
            let classification = match raw {
                INDIRECT_SYMBOL_LOCAL => Some("local"),
                INDIRECT_SYMBOL_ABS => Some("absolute"),
                _ => None,
            };
            let symbol_index = if classification.is_some() {
                None
            } else {
                Some(raw)
            };
            let symbol_index_usize = symbol_index.and_then(|index| usize::try_from(index).ok());
            let symbol = symbol_index.and_then(|_| {
                image
                    .imports
                    .iter()
                    .chain(image.exports.iter())
                    .find(|symbol| symbol_index_usize == Some(symbol.index))
                    .map(|symbol| symbol.name.clone())
            });
            if symbol_index.is_some() && symbol.is_none() {
                image.indirect_symbol_issues.push(format!(
                    "Indirect symbol index {} is absent from the symbol table",
                    raw
                ));
            }
            let Some(file_offset) = section.file_offset.checked_add((slot * stride) as u32) else {
                image.indirect_symbol_issues.push(format!(
                    "Indirect section {} file offset overflowed",
                    section.name
                ));
                continue;
            };
            let valid = symbol.is_some() || classification.is_some();
            image.indirect_symbols.push(IndirectSymbol {
                section: section.name.clone(),
                slot: slot as usize,
                symbol_index,
                symbol,
                source_offset: u64::from(file_offset),
                raw_value: raw,
                classification,
                valid,
            });
        }
    }
}

fn parse_dyld_info(
    bytes: &[u8],
    offset: usize,
    size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if size < 48 {
        return Err(Error::Malformed("Truncated dyld export-info command"));
    }
    let export_offset = read_u32(bytes, offset + 40, little)? as usize;
    let export_size = read_u32(bytes, offset + 44, little)? as usize;
    let rebase_offset = read_u32(bytes, offset + 8, little)? as usize;
    let rebase_size = read_u32(bytes, offset + 12, little)? as usize;
    let bind_offset = read_u32(bytes, offset + 16, little)? as usize;
    let bind_size = read_u32(bytes, offset + 20, little)? as usize;
    let weak_bind_offset = read_u32(bytes, offset + 24, little)? as usize;
    let weak_bind_size = read_u32(bytes, offset + 28, little)? as usize;
    let lazy_bind_offset = read_u32(bytes, offset + 32, little)? as usize;
    let lazy_bind_size = read_u32(bytes, offset + 36, little)? as usize;
    image.dyld_info.push(DyldInfoCommand {
        rebase: dyld_info_range(bytes, rebase_offset, rebase_size),
        bind: dyld_info_range(bytes, bind_offset, bind_size),
        weak_bind: dyld_info_range(bytes, weak_bind_offset, weak_bind_size),
        lazy_bind: dyld_info_range(bytes, lazy_bind_offset, lazy_bind_size),
        exports: dyld_info_range(bytes, export_offset, export_size),
        source_offset: offset as u64,
        source_size: size as u64,
    });
    if export_size == 0 {
        // Export metadata is optional; bind streams below may still be present.
    } else {
        parse_export_trie(bytes, export_offset, export_size, image)?;
    }
    if rebase_size != 0 {
        parse_rebase_stream(bytes, rebase_offset, rebase_size, image)?;
    }
    for (stream_offset, stream_size, stream) in [
        (bind_offset, bind_size, "bind"),
        (weak_bind_offset, weak_bind_size, "weak-bind"),
        (lazy_bind_offset, lazy_bind_size, "lazy-bind"),
    ] {
        if stream_size != 0 {
            if let Err(error) = parse_bind_stream(bytes, stream_offset, stream_size, stream, image)
            {
                image.bind_issues.push(format!("{stream} stream: {error}"));
            }
        }
    }
    Ok(())
}

fn dyld_info_range(bytes: &[u8], offset: usize, size: usize) -> Option<DyldInfoRange> {
    (size != 0).then(|| DyldInfoRange {
        offset: offset as u64,
        size: size as u64,
        valid: size <= MAX_COMMAND_BYTES
            && offset
                .checked_add(size)
                .is_some_and(|end| end <= bytes.len()),
    })
}

fn parse_rebase_stream(
    bytes: &[u8],
    offset: usize,
    size: usize,
    image: &mut Image,
) -> Result<(), Error> {
    let Some(end) = offset.checked_add(size) else {
        image
            .rebase_issues
            .push("Rebase stream range overflowed".into());
        return Ok(());
    };
    if size > MAX_COMMAND_BYTES || offset > bytes.len() {
        image
            .rebase_issues
            .push("Rebase stream exceeds the bounded snapshot".into());
        return Ok(());
    }
    let available_end = end.min(bytes.len());
    if available_end < end {
        image
            .rebase_issues
            .push("Rebase stream is truncated".into());
    }
    let mut cursor = offset;
    let mut rebase_type = 1u8;
    let mut segment = 0u8;
    let mut segment_offset = 0u64;
    for _ in 0..1_000_000 {
        if cursor >= available_end {
            image
                .rebase_issues
                .push("Rebase stream has no DONE opcode".into());
            return Ok(());
        }
        let opcode = bytes[cursor];
        cursor += 1;
        let kind = opcode & 0xf0;
        match kind {
            0x00 => return Ok(()),
            0x10 => rebase_type = opcode & 0x0f,
            0x20 => {
                segment = opcode & 0x0f;
                segment_offset = match read_uleb(bytes, &mut cursor, available_end) {
                    Ok(value) => value,
                    Err(_) => {
                        image
                            .rebase_issues
                            .push("Rebase segment offset is truncated".into());
                        return Ok(());
                    }
                };
            }
            0x30 => {
                let delta = match read_uleb(bytes, &mut cursor, available_end) {
                    Ok(value) => value,
                    Err(_) => {
                        image
                            .rebase_issues
                            .push("Rebase address delta is truncated".into());
                        return Ok(());
                    }
                };
                segment_offset = match segment_offset.checked_add(delta) {
                    Some(value) => value,
                    None => {
                        image.rebase_issues.push("Rebase address overflowed".into());
                        return Ok(());
                    }
                };
            }
            0x40 => segment_offset = segment_offset.saturating_add(u64::from(opcode & 0x0f) * 8),
            0x50 => {
                for _ in 0..(opcode & 0x0f) {
                    record_rebase(image, rebase_type, segment, segment_offset, offset, size);
                    segment_offset = segment_offset.saturating_add(8);
                }
            }
            0x60 => {
                let count = match read_uleb(bytes, &mut cursor, available_end) {
                    Ok(value) => value,
                    Err(_) => {
                        image.rebase_issues.push("Rebase count is truncated".into());
                        return Ok(());
                    }
                };
                for _ in 0..count.min(1_000_000) {
                    record_rebase(image, rebase_type, segment, segment_offset, offset, size);
                    segment_offset = segment_offset.saturating_add(8);
                }
            }
            0x70 => {
                record_rebase(image, rebase_type, segment, segment_offset, offset, size);
                let delta = match read_uleb(bytes, &mut cursor, available_end) {
                    Ok(value) => value,
                    Err(_) => {
                        image
                            .rebase_issues
                            .push("Rebase address delta is truncated".into());
                        return Ok(());
                    }
                };
                segment_offset = segment_offset.saturating_add(8).saturating_add(delta);
            }
            0x80 => {
                let count = match read_uleb(bytes, &mut cursor, available_end) {
                    Ok(value) => value,
                    Err(_) => {
                        image.rebase_issues.push("Rebase count is truncated".into());
                        return Ok(());
                    }
                };
                let skip = match read_uleb(bytes, &mut cursor, available_end) {
                    Ok(value) => value,
                    Err(_) => {
                        image.rebase_issues.push("Rebase skip is truncated".into());
                        return Ok(());
                    }
                };
                for _ in 0..count.min(1_000_000) {
                    record_rebase(image, rebase_type, segment, segment_offset, offset, size);
                    segment_offset = segment_offset.saturating_add(8).saturating_add(skip);
                }
            }
            _ => {
                image
                    .rebase_issues
                    .push(format!("Unsupported rebase opcode 0x{opcode:02x}"));
                return Ok(());
            }
        }
    }
    image
        .rebase_issues
        .push("Rebase stream exceeds the entry limit".into());
    Ok(())
}

fn record_rebase(
    image: &mut Image,
    rebase_type: u8,
    segment: u8,
    offset: u64,
    source_offset: usize,
    source_size: usize,
) {
    let valid = image
        .segments
        .get(usize::from(segment))
        .is_some_and(|segment| offset < segment.file_size);
    if !valid {
        image
            .rebase_issues
            .push(format!("Rebase location is outside segment {segment}"));
    }
    image.rebases.push(Rebase {
        stream: "rebase",
        rebase_type,
        segment,
        offset,
        valid,
        source_offset: source_offset as u64,
        source_size: source_size as u64,
    });
}

fn parse_chained_fixups(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 16 {
        return Err(Error::Malformed("Truncated chained-fixups command"));
    }
    let offset = read_u32(bytes, command + 8, little)? as usize;
    let size = read_u32(bytes, command + 12, little)? as usize;
    image.chained_fixups = Some(ChainedFixups {
        data_offset: offset as u64,
        data_size: size as u64,
        version: None,
        starts_offset: None,
        imports_offset: None,
        imports_count: None,
        imports_format: None,
        symbols_offset: None,
        source_offset: command as u64,
        source_size: command_size as u64,
        valid: false,
    });
    let end = offset
        .checked_add(size)
        .ok_or(Error::Malformed("Chained fixup range overflowed"))?;
    if size < 28 || end > bytes.len() {
        return Err(Error::Malformed("Chained fixup header exceeds the target"));
    }
    let version = read_u32(bytes, offset, true)?;
    if let Some(metadata) = image.chained_fixups.as_mut() {
        metadata.version = Some(version);
    }
    if version != 0 {
        return Err(Error::Unsupported(
            "Unsupported chained fixup header version",
        ));
    }
    let imports_offset = read_u32(bytes, offset + 8, true)? as usize;
    let symbols_offset = read_u32(bytes, offset + 12, true)? as usize;
    let count = read_u32(bytes, offset + 16, true)? as usize;
    let format = read_u32(bytes, offset + 20, true)?;
    if let Some(metadata) = image.chained_fixups.as_mut() {
        metadata.starts_offset = Some(offset as u64 + 4);
        metadata.imports_offset = Some(offset as u64 + imports_offset as u64);
        metadata.imports_count = Some(count as u64);
        metadata.imports_format = Some(format);
        metadata.symbols_offset = Some(offset as u64 + symbols_offset as u64);
    }
    let entry_size = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => return Err(Error::Unsupported("Unsupported chained import format")),
    };
    if read_u32(bytes, offset + 24, true)? != 0 {
        return Err(Error::Unsupported(
            "Compressed chained-fixup symbol names are unsupported",
        ));
    }
    let table = offset
        .checked_add(imports_offset)
        .and_then(|at| at.checked_add(count.checked_mul(entry_size)?))
        .ok_or(Error::Malformed("Chained import table range overflowed"))?;
    let symbols = offset
        .checked_add(symbols_offset)
        .ok_or(Error::Malformed("Chained symbol pool range overflowed"))?;
    if imports_offset < 28 || symbols_offset < imports_offset || table > symbols || symbols > end {
        return Err(Error::Malformed(
            "Chained import table exceeds the fixup data",
        ));
    }
    for index in 0..count {
        let at = offset + imports_offset + index * entry_size;
        let (ordinal, weak, name_offset, addend) = match format {
            1 => {
                let word = read_u32(bytes, at, true)?;
                (
                    sign_extend((word & 0xff) as u64, 8),
                    word & 0x100 != 0,
                    word >> 9,
                    0,
                )
            }
            2 => {
                let word = read_u32(bytes, at, true)?;
                (
                    sign_extend((word & 0xff) as u64, 8),
                    word & 0x100 != 0,
                    word >> 9,
                    i64::from(read_u32(bytes, at + 4, true)? as i32),
                )
            }
            _ => {
                let word = read_u64(bytes, at, true)?;
                (
                    sign_extend(word & 0xffff, 16),
                    word & (1 << 16) != 0,
                    (word >> 32) as u32,
                    read_u64(bytes, at + 8, true)? as i64,
                )
            }
        };
        let name_at = symbols
            .checked_add(name_offset as usize)
            .ok_or(Error::Malformed("Chained symbol name offset overflowed"))?;
        let mut cursor = name_at;
        let name = read_cstring(bytes, &mut cursor, end)?;
        image.chained_imports.push(ChainedImport {
            index,
            symbol: name,
            ordinal: ordinal as i32,
            library: None,
            weak,
            addend,
            source_offset: at as u64,
            source_size: entry_size as u64,
        });
    }
    decode_chained_starts(bytes, offset, size, imports_offset, image)?;
    if let Some(metadata) = image.chained_fixups.as_mut() {
        metadata.valid = true;
    }
    Ok(())
}

fn parse_function_starts(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 16 {
        return Err(Error::Malformed("Truncated LC_FUNCTION_STARTS command"));
    }
    let offset = read_u32(bytes, command + 8, little)? as usize;
    let size = read_u32(bytes, command + 12, little)? as usize;
    let end = match offset.checked_add(size) {
        Some(end) if size <= MAX_COMMAND_BYTES && end <= bytes.len() => end,
        _ => {
            image.function_starts_tables.push(FunctionStartsTable {
                offset: offset as u64,
                size: size as u64,
                source_offset: command as u64,
                source_size: command_size as u64,
                valid: false,
            });
            image
                .function_starts_issues
                .push("Function-starts data exceeds the target".into());
            return Err(Error::Malformed("Function-starts data exceeds the target"));
        }
    };
    image.function_starts_tables.push(FunctionStartsTable {
        offset: offset as u64,
        size: size as u64,
        source_offset: command as u64,
        source_size: command_size as u64,
        valid: true,
    });
    let base = image
        .segments
        .iter()
        .find(|segment| segment.name == "__TEXT")
        .map(|segment| segment.vm_address)
        .ok_or_else(|| {
            image
                .function_starts_issues
                .push("Function-starts __TEXT image base is unavailable".into());
            Error::Malformed("Function-starts image base is unavailable")
        })?;
    let mut cursor = offset;
    let mut address = base;
    for _ in 0..1_000_000 {
        let record_offset = cursor;
        let delta = match read_uleb(bytes, &mut cursor, end) {
            Ok(delta) => delta,
            Err(error) => {
                image
                    .function_starts_issues
                    .push("Function-starts ULEB delta is truncated or malformed".into());
                return Err(error);
            }
        };
        if delta == 0 {
            return Ok(());
        }
        address = match address.checked_add(delta) {
            Some(address) => address,
            None => {
                image
                    .function_starts_issues
                    .push("Function-starts address overflowed".into());
                return Err(Error::Malformed("Function-starts address overflowed"));
            }
        };
        let valid = image.segments.iter().any(|segment| {
            segment.initial_permissions.execute
                && address >= segment.vm_address
                && address - segment.vm_address < segment.vm_size
        });
        if !valid {
            image.function_starts_issues.push(format!(
                "Function-start address 0x{address:x} is outside executable ranges"
            ));
        }
        image.function_start_records.push(FunctionStart {
            address,
            delta,
            source_offset: record_offset as u64,
            source_size: (cursor - record_offset) as u64,
            valid,
        });
        image.function_starts.push(address);
    }
    image
        .function_starts_issues
        .push("Function-starts table exceeds the entry limit".into());
    Err(Error::Unsupported(
        "Function-starts table exceeds the entry limit",
    ))
}

fn parse_data_in_code(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 16 {
        return Err(Error::Malformed("Truncated LC_DATA_IN_CODE command"));
    }
    let offset = read_u32(bytes, command + 8, little)? as usize;
    let size = read_u32(bytes, command + 12, little)? as usize;
    let table_valid = size <= MAX_COMMAND_BYTES
        && offset
            .checked_add(size)
            .is_some_and(|end| end <= bytes.len());
    image.data_in_code_tables.push(DataInCodeTable {
        offset: offset as u64,
        size: size as u64,
        source_offset: command as u64,
        source_size: command_size as u64,
        valid: table_valid,
    });
    if size > MAX_COMMAND_BYTES {
        image
            .data_in_code_issues
            .push("LC_DATA_IN_CODE table exceeds the 16 MiB limit".into());
        return Ok(());
    }
    let Some(end) = offset.checked_add(size) else {
        image
            .data_in_code_issues
            .push("LC_DATA_IN_CODE table range overflowed".into());
        return Ok(());
    };
    if offset > bytes.len() {
        image
            .data_in_code_issues
            .push("LC_DATA_IN_CODE table starts beyond the snapshot".into());
        return Ok(());
    }
    let available_end = end.min(bytes.len());
    if available_end < end {
        image
            .data_in_code_issues
            .push("LC_DATA_IN_CODE table is truncated".into());
    }
    let available_bytes = available_end - offset;
    let complete_bytes = available_bytes / 8 * 8;
    if complete_bytes != available_bytes || complete_bytes != size / 8 * 8 {
        image
            .data_in_code_issues
            .push("LC_DATA_IN_CODE table has a partial record".into());
    }
    for record_offset in (offset..offset + complete_bytes).step_by(8) {
        let file_offset = read_u32(bytes, record_offset, little)? as u64;
        let length = read_u16(bytes, record_offset + 4, little)?;
        let kind = read_u16(bytes, record_offset + 6, little)?;
        let record_end = file_offset.checked_add(u64::from(length));
        let valid = record_end.is_some_and(|end| end <= bytes.len() as u64);
        if !valid {
            image.data_in_code_issues.push(format!(
                "LC_DATA_IN_CODE record at table offset {record_offset} exceeds the snapshot"
            ));
        }
        image.data_in_code.push(DataInCodeRecord {
            offset: file_offset,
            length,
            kind,
            kind_name: data_in_code_kind_name(kind).to_owned(),
            source_offset: record_offset as u64,
            source_size: 8,
            valid,
        });
    }
    Ok(())
}

fn parse_encryption_info(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    command_kind: u32,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    let required_size = if command_kind == 0x2c { 24 } else { 20 };
    if command_size < required_size {
        return Err(Error::Malformed("Truncated encryption-info command"));
    }
    let offset = read_u32(bytes, command + 8, little)? as u64;
    let size = read_u32(bytes, command + 12, little)? as u64;
    let crypt_id = read_u32(bytes, command + 16, little)?;
    let end = offset.checked_add(size);
    let valid = end.is_some_and(|end| end <= bytes.len() as u64);
    if end.is_none() {
        image
            .encryption_issues
            .push("Encryption range overflowed".into());
    } else if !valid {
        image
            .encryption_issues
            .push("Encryption range exceeds the snapshot".into());
    }
    let state = if !valid {
        "unknown"
    } else if crypt_id == 0 {
        "unencrypted"
    } else {
        "encrypted"
    };
    image.encryption_info.push(EncryptionInfo {
        offset,
        size,
        crypt_id,
        valid,
        state,
        source_offset: command as u64,
        source_size: command_size as u64,
    });
    Ok(())
}

fn parse_note(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 40 {
        return Err(Error::Malformed("Truncated LC_NOTE command"));
    }
    let owner_bytes = bytes
        .get(command + 8..command + 24)
        .ok_or(Error::Malformed("LC_NOTE owner is truncated"))?
        .to_vec();
    let owner_end = owner_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(owner_bytes.len());
    let owner_value = &owner_bytes[..owner_end];
    let owner_utf8_valid = std::str::from_utf8(owner_value).is_ok();
    let owner = String::from_utf8_lossy(owner_value).into_owned();
    if !owner_utf8_valid {
        image
            .note_issues
            .push("LC_NOTE owner is not valid UTF-8".into());
    }
    let offset = read_u64(bytes, command + 24, little)?;
    let size = read_u64(bytes, command + 32, little)?;
    let end = offset.checked_add(size);
    let aligned = offset % 4 == 0;
    let valid = end.is_some_and(|end| end <= bytes.len() as u64);
    if !aligned {
        image
            .note_issues
            .push(format!("LC_NOTE range at {offset} is not 4-byte aligned"));
    }
    if end.is_none() {
        image.note_issues.push("LC_NOTE range overflowed".into());
    } else if !valid {
        image
            .note_issues
            .push("LC_NOTE range exceeds the snapshot".into());
    }
    image.notes.push(Note {
        owner,
        owner_bytes,
        owner_utf8_valid,
        offset,
        size,
        source_offset: command as u64,
        source_size: command_size as u64,
        aligned,
        valid,
    });
    Ok(())
}

fn parse_code_signature(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 16 {
        return Err(Error::Malformed("Truncated LC_CODE_SIGNATURE command"));
    }
    let offset = read_u32(bytes, command + 8, little)? as usize;
    let size = read_u32(bytes, command + 12, little)? as usize;
    let range_valid = offset
        .checked_add(size)
        .is_some_and(|end| end <= bytes.len() && size <= MAX_COMMAND_BYTES);
    image.code_signature_commands.push(CodeSignatureCommand {
        blob_offset: offset as u64,
        blob_size: size as u64,
        source_offset: command as u64,
        source_size: command_size as u64,
        valid: range_valid,
    });
    let Some(end) = offset.checked_add(size) else {
        add_code_signature_issue(
            image,
            "range_overflow",
            Some(offset as u64),
            "LC_CODE_SIGNATURE range overflowed",
        );
        return Ok(());
    };
    if size > MAX_COMMAND_BYTES {
        add_code_signature_issue(
            image,
            "size_limit",
            Some(offset as u64),
            "LC_CODE_SIGNATURE exceeds the 16 MiB limit",
        );
        return Ok(());
    }
    if offset >= bytes.len() {
        add_code_signature_issue(
            image,
            "truncated",
            Some(offset as u64),
            "LC_CODE_SIGNATURE starts beyond the snapshot",
        );
        return Ok(());
    }
    let blob_end = end.min(bytes.len());
    if blob_end < end {
        add_code_signature_issue(
            image,
            "truncated",
            Some(offset as u64),
            "LC_CODE_SIGNATURE is truncated",
        );
    }
    let magic = match read_be32_at(bytes, offset, blob_end) {
        Ok(magic) => magic,
        Err(_) => {
            add_code_signature_issue(
                image,
                "truncated",
                Some(offset as u64),
                "LC_CODE_SIGNATURE blob header is truncated",
            );
            return Ok(());
        }
    };
    if magic == 0xfade_0cc0 {
        parse_super_blob(bytes, offset, blob_end, image)?;
    } else if magic == 0xfade_0c02 {
        let signature = parse_code_directory(bytes, offset, blob_end, None, image)?;
        image.code_signatures.push(signature);
    } else {
        add_code_signature_issue(
            image,
            "unsupported_magic",
            Some(offset as u64),
            "LC_CODE_SIGNATURE blob has an unsupported magic",
        );
    }
    Ok(())
}

fn parse_super_blob(
    bytes: &[u8],
    base: usize,
    available_end: usize,
    image: &mut Image,
) -> Result<(), Error> {
    if base.checked_add(12).is_none_or(|end| end > available_end) {
        add_code_signature_issue(
            image,
            "truncated",
            Some(base as u64),
            "Code signature superblob header is truncated",
        );
        return Ok(());
    }
    let declared_length = read_be32_at(bytes, base + 4, available_end)? as usize;
    let count = read_be32_at(bytes, base + 8, available_end)? as usize;
    if count > MAX_SYMBOLS {
        add_code_signature_issue(
            image,
            "entry_limit",
            Some(base as u64),
            "Code signature superblob entry count exceeds the limit",
        );
        return Ok(());
    }
    let blob_end = base
        .checked_add(declared_length)
        .ok_or(Error::Malformed(
            "Code signature superblob length overflowed",
        ))?
        .min(available_end);
    if declared_length < 12 || blob_end < base + 12 + count.saturating_mul(8) {
        add_code_signature_issue(
            image,
            "truncated",
            Some(base as u64),
            "Code signature superblob index is truncated",
        );
        return Ok(());
    }
    let mut entitlement_range = None;
    let mut code_directories = Vec::new();
    for index in 0..count {
        let entry = base + 12 + index * 8;
        let kind = read_be32_at(bytes, entry, blob_end)?;
        let relative_offset = read_be32_at(bytes, entry + 4, blob_end)? as usize;
        let Some(blob) = base.checked_add(relative_offset) else {
            add_code_signature_issue(
                image,
                "range_overflow",
                Some(base as u64),
                "Code signature blob offset overflowed",
            );
            continue;
        };
        let mut child = CodeSignatureChild {
            slot_type: kind,
            offset: blob as u64,
            size: 0,
            magic: None,
            valid: false,
        };
        if blob + 8 > blob_end {
            add_code_signature_issue(
                image,
                "truncated",
                Some(blob as u64),
                "Code signature indexed blob is truncated",
            );
            image.code_signature_children.push(child);
            continue;
        }
        let blob_magic = read_be32_at(bytes, blob, blob_end)?;
        let blob_length = read_be32_at(bytes, blob + 4, blob_end)? as usize;
        child.size = blob_length as u64;
        child.magic = Some(blob_magic);
        let blob_end_for_entry = blob
            .checked_add(blob_length)
            .unwrap_or(blob_end)
            .min(blob_end);
        if blob_end_for_entry < blob + blob_length {
            add_code_signature_issue(
                image,
                "truncated",
                Some(blob as u64),
                "Code signature indexed blob is truncated",
            );
        }
        child.valid = blob_end_for_entry == blob + blob_length;
        image.code_signature_children.push(child);
        if kind == 5 || blob_magic == 0xfade_7171 {
            entitlement_range = Some((blob as u64, blob_length as u64));
        } else if blob_magic == 0xfade_0c02 {
            code_directories.push((blob, blob_end_for_entry));
        }
    }
    if code_directories.is_empty() {
        add_code_signature_issue(
            image,
            "missing_code_directory",
            Some(base as u64),
            "Code signature superblob has no CodeDirectory",
        );
    }
    for (directory, directory_end) in code_directories {
        let signature =
            parse_code_directory(bytes, directory, directory_end, entitlement_range, image)?;
        image.code_signatures.push(signature);
    }
    Ok(())
}

fn parse_code_directory(
    bytes: &[u8],
    base: usize,
    blob_end: usize,
    entitlement_range: Option<(u64, u64)>,
    image: &mut Image,
) -> Result<CodeSignature, Error> {
    let length = read_be32_at(bytes, base + 4, blob_end)? as usize;
    let signature_end = base
        .checked_add(length)
        .ok_or(Error::Malformed("CodeDirectory length overflowed"))?;
    let valid_end = signature_end.min(blob_end);
    if valid_end < signature_end {
        add_code_signature_issue(
            image,
            "truncated",
            Some(base as u64),
            "CodeDirectory is truncated",
        );
    }
    if length < 40 || valid_end < base + 40 {
        add_code_signature_issue(
            image,
            "truncated",
            Some(base as u64),
            "CodeDirectory header is truncated",
        );
        return Ok(CodeSignature {
            offset: base as u64,
            size: length as u64,
            valid: false,
            identifier: None,
            team_id: None,
            flags: None,
            hash_type: None,
            hash_size: None,
            platform: None,
            signature_verification: "not_performed",
            entitlements_offset: entitlement_range.map(|range| range.0),
            entitlements_size: entitlement_range.map(|range| range.1),
        });
    }
    let flags = read_be32_at(bytes, base + 12, valid_end)?;
    let identifier_offset = read_be32_at(bytes, base + 20, valid_end)? as usize;
    let identifier = code_directory_string(bytes, base, identifier_offset, valid_end, image);
    let version = read_be32_at(bytes, base + 8, valid_end)?;
    let team_offset = if version >= 0x20200 && length >= 52 {
        read_be32_at(bytes, base + 48, valid_end).ok()
    } else {
        None
    };
    let team_id = team_offset
        .and_then(|offset| code_directory_string(bytes, base, offset as usize, valid_end, image));
    let hash_type = bytes.get(base + 37).copied();
    let hash_size = bytes.get(base + 36).copied();
    let platform = bytes.get(base + 38).copied();
    Ok(CodeSignature {
        offset: base as u64,
        size: length as u64,
        valid: valid_end == signature_end,
        identifier,
        team_id,
        flags: Some(flags),
        hash_type,
        hash_size,
        platform,
        signature_verification: "not_performed",
        entitlements_offset: entitlement_range.map(|range| range.0),
        entitlements_size: entitlement_range.map(|range| range.1),
    })
}

fn code_directory_string(
    bytes: &[u8],
    base: usize,
    relative_offset: usize,
    end: usize,
    image: &mut Image,
) -> Option<String> {
    let Some(start) = base.checked_add(relative_offset) else {
        add_code_signature_issue(
            image,
            "range_overflow",
            Some(base as u64),
            "CodeDirectory string offset overflowed",
        );
        return None;
    };
    if start >= end {
        add_code_signature_issue(
            image,
            "invalid_offset",
            Some(start as u64),
            "CodeDirectory string offset is outside the blob",
        );
        return None;
    }
    let tail = &bytes[start..end];
    let string_end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    Some(String::from_utf8_lossy(&tail[..string_end]).into_owned())
}

fn add_code_signature_issue(
    image: &mut Image,
    kind: &'static str,
    offset: Option<u64>,
    message: &str,
) {
    image.code_signature_issues.push(CodeSignatureIssue {
        kind,
        offset,
        message: message.into(),
    });
}

fn decode_chained_starts(
    bytes: &[u8],
    base: usize,
    size: usize,
    imports_offset: usize,
    image: &mut Image,
) -> Result<(), Error> {
    let end = base + size;
    let starts_offset = read_u32(bytes, base + 4, true)? as usize;
    let starts = base
        .checked_add(starts_offset)
        .ok_or(Error::Malformed("Chained starts offset overflowed"))?;
    if starts + 4 > end || starts >= base + imports_offset {
        return Err(Error::Malformed(
            "Chained starts table exceeds its fixup data",
        ));
    }
    let segment_count = read_u32(bytes, starts, true)? as usize;
    if segment_count > image.segments.len() {
        return Err(Error::Malformed(
            "Chained starts segment count exceeds Mach-O layout",
        ));
    }
    if starts + 4 + segment_count * 4 > base + imports_offset {
        return Err(Error::Malformed(
            "Chained starts segment table is truncated",
        ));
    }
    for segment_index in 0..segment_count {
        let info_offset = read_u32(bytes, starts + 4 + segment_index * 4, true)? as usize;
        if info_offset == 0 {
            continue;
        }
        let info = starts
            .checked_add(info_offset)
            .ok_or(Error::Malformed("Chained segment info offset overflowed"))?;
        if info + 22 > base + imports_offset {
            return Err(Error::Malformed("Chained segment info is truncated"));
        }
        let info_size = read_u32(bytes, info, true)? as usize;
        let page_size = usize::from(read_u16(bytes, info + 4, true)?);
        let pointer_format = read_u16(bytes, info + 6, true)?;
        let segment_offset = read_u64(bytes, info + 8, true)?;
        let page_count = usize::from(read_u16(bytes, info + 20, true)?);
        if info_size < 22 + page_count * 2 || info + info_size > base + imports_offset {
            return Err(Error::Malformed("Chained page starts exceed segment table"));
        }
        if page_size != 0x1000 && page_size != 0x4000 {
            return Err(Error::Malformed(
                "Chained page size must be 4096 or 16384 bytes",
            ));
        }
        let supported = matches!(pointer_format, 1 | 2 | 6 | 7 | 8 | 9 | 12);
        if !supported {
            if !image.chained_unsupported_formats.contains(&pointer_format) {
                image.chained_unsupported_formats.push(pointer_format);
            }
            continue;
        }
        let segment = image.segments[segment_index].clone();
        if segment_offset != segment.vm_address {
            return Err(Error::Malformed(
                "Chained segment offset disagrees with Mach-O layout",
            ));
        }
        for page in 0..page_count {
            let start = read_u16(bytes, info + 22 + page * 2, true)?;
            if start == 0xffff {
                continue;
            }
            walk_chain(
                bytes,
                segment_index,
                &segment,
                page,
                page_size,
                start,
                pointer_format,
                image,
            )?;
        }
    }
    Ok(())
}

fn walk_chain(
    bytes: &[u8],
    segment_index: usize,
    segment: &Segment,
    page: usize,
    page_size: usize,
    start: u16,
    format: u16,
    image: &mut Image,
) -> Result<(), Error> {
    let mut relative = page * page_size + usize::from(start);
    let stride = 4usize;
    for _ in 0..4096 {
        let file_offset = segment
            .file_offset
            .checked_add(relative as u64)
            .ok_or(Error::Malformed("Chained pointer file offset overflowed"))?;
        let at = usize::try_from(file_offset)
            .map_err(|_| Error::Malformed("Chained pointer offset is out of range"))?;
        let raw = read_u64(bytes, at, true)?;
        let arm64e = matches!(format, 1 | 7 | 8);
        let bind = if arm64e {
            raw & (1 << 62) != 0
        } else {
            raw >> 63 != 0
        };
        let diversity = if arm64e {
            Some(((raw >> 32) & 0xffff) as u16)
        } else {
            None
        };
        let address_diversity = arm64e.then(|| raw & (1 << 48) != 0);
        let key = arm64e.then(|| ((raw >> 49) & 0x3) as u8);
        let authenticated = arm64e.then(|| raw & (1 << 63) != 0);
        let (target, import_index) = if bind {
            let index = (raw
                & if format == 12 {
                    0x00ff_ffff
                } else if matches!(format, 1 | 7 | 8 | 9) {
                    0x0000_ffff
                } else {
                    0x00ff_ffff
                }) as usize;
            if index >= image.chained_imports.len() {
                return Err(Error::Malformed(
                    "Chained bind ordinal is outside the import table",
                ));
            }
            (None, Some(index))
        } else {
            let raw_target = if arm64e && authenticated == Some(true) {
                raw & 0xffff_ffff
            } else if arm64e {
                (raw & ((1u64 << 43) - 1)) | (((raw >> 43) & 0xff) << 56)
            } else if matches!(format, 2 | 6) {
                (raw & 0x0000_ffff_ffff_ffff) | ((raw >> 36 & 0xff) << 56)
            } else {
                raw & 0xffff_ffff
            };
            let target = if arm64e || format == 6 || matches!(format, 9 | 12) {
                segment.vm_address.checked_add(raw_target)
            } else {
                Some(raw_target)
            };
            (target, None)
        };
        image.chained_pointers.push(ChainedPointer {
            segment: segment_index,
            file_offset,
            raw,
            kind: if bind { "bind" } else { "rebase" },
            target,
            import_index,
            diversity,
            address_diversity,
            key,
            authenticated,
        });
        let next = ((raw >> 51) & 0x7ff) as usize;
        if next == 0 {
            return Ok(());
        }
        relative = relative
            .checked_add(next * stride)
            .ok_or(Error::Malformed("Chained pointer walk overflowed"))?;
        if relative >= segment.file_size as usize {
            return Err(Error::Malformed("Chained pointer walk leaves its segment"));
        }
    }
    Err(Error::Malformed(
        "Chained pointer walk exceeds the chain limit",
    ))
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn parse_bind_stream(
    bytes: &[u8],
    offset: usize,
    size: usize,
    stream: &'static str,
    image: &mut Image,
) -> Result<(), Error> {
    const MAX_OPS: usize = 1_000_000;
    let end = offset
        .checked_add(size)
        .ok_or(Error::Malformed("Mach-O bind stream range overflowed"))?;
    if end > bytes.len() || size > MAX_COMMAND_BYTES {
        return Err(Error::Malformed(
            "Mach-O bind stream is truncated or exceeds the limit",
        ));
    }
    let mut cursor = offset;
    let mut ordinal = 0i32;
    let mut symbol = String::new();
    let mut bind_type = 1u8;
    let mut segment = 0u8;
    let mut address = 0u64;
    let mut addend = 0i64;
    let mut weak_import = false;
    for _ in 0..MAX_OPS {
        let opcode = *bytes
            .get(cursor)
            .ok_or(Error::Malformed("Mach-O bind opcode is truncated"))?;
        cursor += 1;
        let operation = opcode & 0xf0;
        let immediate = opcode & 0x0f;
        match operation {
            0x00 => return Ok(()),
            0x10 => ordinal = i32::from(immediate),
            0x20 => {
                ordinal = i32::try_from(read_uleb(bytes, &mut cursor, end)?)
                    .map_err(|_| Error::Malformed("Mach-O bind ordinal is out of range"))?
            }
            0x30 => {
                ordinal = i32::from((immediate as i8) | if immediate & 8 != 0 { !0x0f } else { 0 })
            }
            0x40 => {
                symbol = read_cstring(bytes, &mut cursor, end)?;
                weak_import = immediate & 1 != 0;
            }
            0x50 => bind_type = immediate,
            0x60 => addend = read_sleb(bytes, &mut cursor, end)?,
            0x70 => {
                segment = immediate;
                address = read_uleb(bytes, &mut cursor, end)?;
            }
            0x80 => address = address.saturating_add(read_uleb(bytes, &mut cursor, end)?),
            0x90 => push_bind(
                image,
                stream,
                &symbol,
                ordinal,
                bind_type,
                segment,
                address,
                addend,
                weak_import,
                offset,
                size,
            ),
            0xa0 => {
                return Err(Error::Unsupported(
                    "Mach-O threaded bind opcodes are unsupported",
                ));
            }
            0xb0 => {
                push_bind(
                    image,
                    stream,
                    &symbol,
                    ordinal,
                    bind_type,
                    segment,
                    address,
                    addend,
                    weak_import,
                    offset,
                    size,
                );
                address =
                    address
                        .saturating_add(8)
                        .saturating_add(read_uleb(bytes, &mut cursor, end)?);
            }
            0xc0 => {
                push_bind(
                    image,
                    stream,
                    &symbol,
                    ordinal,
                    bind_type,
                    segment,
                    address,
                    addend,
                    weak_import,
                    offset,
                    size,
                );
                address = address.saturating_add(8u64.saturating_mul(u64::from(immediate)));
            }
            0xd0 => {
                let count = read_uleb(bytes, &mut cursor, end)?;
                let skip = read_uleb(bytes, &mut cursor, end)?;
                for _ in 0..count.min(MAX_OPS as u64) {
                    push_bind(
                        image,
                        stream,
                        &symbol,
                        ordinal,
                        bind_type,
                        segment,
                        address,
                        addend,
                        weak_import,
                        offset,
                        size,
                    );
                    address = address.saturating_add(8).saturating_add(skip);
                }
            }
            _ => return Err(Error::Malformed("Unknown Mach-O bind opcode")),
        }
    }
    Err(Error::Unsupported(
        "Mach-O bind stream exceeds the opcode limit",
    ))
}

fn push_bind(
    image: &mut Image,
    stream: &'static str,
    symbol: &str,
    ordinal: i32,
    bind_type: u8,
    segment: u8,
    offset: u64,
    addend: i64,
    weak_import: bool,
    source_offset: usize,
    source_size: usize,
) {
    image.binds.push(Bind {
        stream,
        symbol: symbol.to_owned(),
        ordinal,
        library: None,
        bind_type,
        segment,
        offset,
        addend,
        weak_import,
        source_offset: source_offset as u64,
        source_size: source_size as u64,
    });
}

fn resolve_ordinals(image: &mut Image) {
    for bind in &mut image.binds {
        bind.library = ordinal_library(bind.ordinal, &image.dependencies);
    }
    for import in &mut image.chained_imports {
        import.library = ordinal_library(import.ordinal, &image.dependencies);
    }
}

fn ordinal_library(ordinal: i32, dependencies: &[Dependency]) -> Option<String> {
    match ordinal {
        value if value > 0 => dependencies
            .get((value - 1) as usize)
            .map(|dependency| dependency.path.clone()),
        -1 => Some("self".into()),
        -2 => Some("main-executable".into()),
        -3 => Some("flat-lookup".into()),
        -4 => Some("weak-lookup".into()),
        _ => None,
    }
}

fn parse_export_trie(
    bytes: &[u8],
    offset: usize,
    size: usize,
    image: &mut Image,
) -> Result<(), Error> {
    const MAX_NODES: usize = 1_000_000;
    let end = offset
        .checked_add(size)
        .ok_or(Error::Malformed("Mach-O export trie range overflowed"))?;
    if end > bytes.len() || size > MAX_COMMAND_BYTES {
        return Err(Error::Malformed(
            "Mach-O export trie is truncated or exceeds the limit",
        ));
    }
    let image_base = image
        .segments
        .iter()
        .find(|segment| segment.file_offset == 0 && segment.file_size > 0)
        .map(|segment| segment.vm_address)
        .unwrap_or(0);
    let mut stack = vec![(0usize, String::new())];
    let mut visited = std::collections::BTreeSet::new();
    while let Some((node, prefix)) = stack.pop() {
        if visited.len() >= MAX_NODES {
            return Err(Error::Unsupported(
                "Mach-O export trie exceeds the node limit",
            ));
        }
        let absolute = offset
            .checked_add(node)
            .ok_or(Error::Malformed("Mach-O export trie node overflowed"))?;
        if absolute >= end || !visited.insert(node) {
            continue;
        }
        let mut cursor = absolute;
        let terminal_size = read_uleb(bytes, &mut cursor, end)? as usize;
        let terminal_end = cursor
            .checked_add(terminal_size)
            .ok_or(Error::Malformed("Mach-O export trie terminal overflowed"))?;
        if terminal_end > end {
            return Err(Error::Malformed("Mach-O export trie terminal is truncated"));
        }
        if terminal_size > 0 {
            let mut terminal = cursor;
            let terminal_offset = terminal;
            let flags = read_uleb(bytes, &mut terminal, terminal_end)?;
            let reexport = flags & 0x08 != 0;
            let (address, resolver, ordinal, source, source_symbol) = if reexport {
                let ordinal = read_uleb(bytes, &mut terminal, terminal_end)?;
                let name = read_cstring(bytes, &mut terminal, terminal_end)?;
                (
                    None,
                    None,
                    Some(ordinal),
                    None,
                    Some(name).filter(|value| !value.is_empty()),
                )
            } else {
                let value = read_uleb(bytes, &mut terminal, terminal_end)?;
                let address = image_base.checked_add(value);
                let resolver = if flags & 0x10 != 0 {
                    Some(image_base.checked_add(read_uleb(bytes, &mut terminal, terminal_end)?))
                        .flatten()
                } else {
                    None
                };
                (address, resolver, None, None, None)
            };
            let kind = if reexport {
                "reexport"
            } else {
                match flags & 0x03 {
                    1 => "thread-local",
                    2 => "absolute",
                    0 => "regular",
                    _ => "unknown",
                }
            };
            image.export_records.push(ExportRecord {
                name: prefix.clone(),
                flags,
                flag_names: export_flag_names(flags),
                kind,
                address,
                resolver,
                reexport_ordinal: ordinal,
                source_symbol: source_symbol.clone(),
                terminal_offset: terminal_offset as u64,
                source_offset: terminal_offset as u64,
                source_size: terminal_size as u64,
                valid: true,
            });
            image.exports.push(Symbol {
                index: image.exports.len(),
                name: prefix.clone(),
                address: address.unwrap_or(0),
                weak: flags & 0x04 != 0,
                reexport,
                source,
                source_symbol,
            });
        }
        cursor = terminal_end;
        let child_count = *bytes.get(cursor).ok_or(Error::Malformed(
            "Mach-O export trie children are truncated",
        ))? as usize;
        cursor += 1;
        for _ in 0..child_count {
            let edge = read_cstring(bytes, &mut cursor, end)?;
            let child = read_uleb(bytes, &mut cursor, end)? as usize;
            let mut name = prefix.clone();
            name.push_str(&edge);
            stack.push((child, name));
        }
    }
    Ok(())
}

fn read_uleb(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<u64, Error> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        if *cursor >= end {
            return Err(Error::Malformed("Mach-O export trie ULEB is truncated"));
        }
        let byte = *bytes
            .get(*cursor)
            .ok_or(Error::Malformed("Mach-O export trie ULEB is truncated"))?;
        *cursor += 1;
        value = value
            .checked_add(
                u64::from(byte & 0x7f)
                    .checked_shl(shift)
                    .ok_or(Error::Malformed("Mach-O export trie ULEB overflowed"))?,
            )
            .ok_or(Error::Malformed("Mach-O export trie ULEB overflowed"))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    let _ = end;
    Err(Error::Malformed("Mach-O export trie ULEB is too long"))
}

fn read_sleb(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<i64, Error> {
    let mut value = 0i64;
    let mut shift = 0u32;
    for _ in 0..10 {
        if *cursor >= end {
            return Err(Error::Malformed("Mach-O bind SLEB is truncated"));
        }
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= !0i64 << shift;
            }
            return Ok(value);
        }
    }
    Err(Error::Malformed("Mach-O bind SLEB is too long"))
}

fn read_cstring(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<String, Error> {
    let start = *cursor;
    while *cursor < end && bytes[*cursor] != 0 {
        *cursor += 1;
    }
    if *cursor >= end {
        return Err(Error::Malformed(
            "Mach-O export trie string is unterminated",
        ));
    }
    let value = String::from_utf8_lossy(&bytes[start..*cursor]).into_owned();
    *cursor += 1;
    Ok(value)
}

/// Reads a command-relative C string without crossing the command boundary.
fn bounded_string(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    relative: usize,
) -> Option<String> {
    let end = command.checked_add(command_size)?;
    let start = command.checked_add(relative)?;
    if start >= end {
        return None;
    }
    let raw = bytes.get(start..end)?;
    let terminator = raw.iter().position(|byte| *byte == 0)?;
    Some(String::from_utf8_lossy(&raw[..terminator]).into_owned())
}

fn parse_path_record(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    relative: usize,
    little: bool,
    image: &mut Image,
) -> PathRecord {
    let mut record = PathRecord {
        value: None,
        raw_bytes: Vec::new(),
        utf8_valid: false,
        command_offset: command as u64,
        command_size: command_size as u64,
        string_offset: None,
        string_source_offset: None,
        string_source_size: 0,
        valid: false,
    };
    if command_size < relative + 4 {
        image
            .path_issues
            .push("Mach-O path command is truncated before its string offset".into());
        return record;
    }
    let string_offset = match read_u32(bytes, command + relative, little) {
        Ok(value) => value as usize,
        Err(_) => {
            image
                .path_issues
                .push("Mach-O path string offset is truncated".into());
            return record;
        }
    };
    record.string_offset = Some(string_offset as u64);
    if string_offset >= command_size {
        image
            .path_issues
            .push("Mach-O path string offset is outside the command".into());
        return record;
    }
    let Some(start) = command.checked_add(string_offset) else {
        image
            .path_issues
            .push("Mach-O path string offset overflowed".into());
        return record;
    };
    let Some(end) = command.checked_add(command_size) else {
        image
            .path_issues
            .push("Mach-O path command range overflowed".into());
        return record;
    };
    let Some(raw) = bytes.get(start..end) else {
        image
            .path_issues
            .push("Mach-O path command is outside the snapshot".into());
        return record;
    };
    let terminated = raw.iter().position(|byte| *byte == 0);
    let value_end = terminated.unwrap_or(raw.len());
    let raw_end = terminated.map_or(value_end, |end| end + 1);
    record.raw_bytes = raw[..raw_end].to_vec();
    record.value = String::from_utf8(raw[..value_end].to_vec()).ok();
    record.utf8_valid = record.value.is_some();
    record.string_source_offset = Some(start as u64);
    record.string_source_size = raw_end as u64;
    record.valid = terminated.is_some() && record.utf8_valid;
    if terminated.is_none() {
        image
            .path_issues
            .push("Mach-O path string is unterminated".into());
    }
    if !record.utf8_valid {
        image
            .path_issues
            .push("Mach-O path string is not valid UTF-8".into());
    }
    record
}

fn parse_linker_option(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    image: &mut Image,
) -> Result<(), Error> {
    if command_size < 12 {
        image
            .path_issues
            .push("Truncated LC_LINKER_OPTION command".into());
        image.linker_options.push(LinkerOptionCommand {
            declared_count: 0,
            options: Vec::new(),
            raw_options: Vec::new(),
            option_records: Vec::new(),
            command_offset: command as u64,
            command_size: command_size as u64,
            valid: false,
        });
        return Ok(());
    }
    let declared_count = read_u32(bytes, command + 8, little)?;
    let mut cursor = command + 12;
    let end = command
        .checked_add(command_size)
        .ok_or(Error::Malformed("LC_LINKER_OPTION range overflowed"))?;
    let mut options = Vec::new();
    let mut raw_options = Vec::new();
    let mut option_records = Vec::new();
    for _ in 0..declared_count.min(4096) {
        if cursor >= end {
            image
                .path_issues
                .push("LC_LINKER_OPTION string table is truncated".into());
            break;
        }
        let record_offset = cursor;
        let raw = &bytes[cursor..end];
        let Some(terminator) = raw.iter().position(|byte| *byte == 0) else {
            raw_options.push(raw.to_vec());
            options.push(String::from_utf8_lossy(raw).into_owned());
            let utf8_valid = std::str::from_utf8(raw).is_ok();
            if !utf8_valid {
                image
                    .path_issues
                    .push("LC_LINKER_OPTION string is not valid UTF-8".into());
            }
            option_records.push(LinkerOptionRecord {
                value: std::str::from_utf8(raw).ok().map(str::to_owned),
                raw_bytes: raw.to_vec(),
                source_offset: record_offset as u64,
                source_size: raw.len() as u64,
                terminated: false,
                utf8_valid,
                valid: false,
            });
            image
                .path_issues
                .push("LC_LINKER_OPTION string is unterminated".into());
            break;
        };
        let value_bytes = &raw[..terminator];
        let utf8_valid = std::str::from_utf8(value_bytes).is_ok();
        if !utf8_valid {
            image
                .path_issues
                .push("LC_LINKER_OPTION string is not valid UTF-8".into());
        }
        raw_options.push(value_bytes.to_vec());
        options.push(String::from_utf8_lossy(value_bytes).into_owned());
        option_records.push(LinkerOptionRecord {
            value: std::str::from_utf8(value_bytes).ok().map(str::to_owned),
            raw_bytes: value_bytes.to_vec(),
            source_offset: record_offset as u64,
            source_size: (terminator + 1) as u64,
            terminated: true,
            utf8_valid,
            valid: utf8_valid,
        });
        cursor += terminator + 1;
    }
    if declared_count > 4096 {
        image
            .path_issues
            .push("LC_LINKER_OPTION count exceeds the bounded limit".into());
    }
    let valid = options.len() == declared_count as usize;
    let options_valid = option_records.iter().all(|record| record.valid);
    image.linker_options.push(LinkerOptionCommand {
        declared_count,
        options,
        raw_options,
        option_records,
        command_offset: command as u64,
        command_size: command_size as u64,
        valid: valid && options_valid,
    });
    Ok(())
}

fn parse_dylib(
    bytes: &[u8],
    command: usize,
    command_size: usize,
    little: bool,
    kind: &'static str,
    image: &mut Image,
) -> DylibRecord {
    let mut record = DylibRecord {
        kind,
        encoding: "dylib_command",
        name: None,
        name_bytes: Vec::new(),
        name_utf8_valid: false,
        name_offset: None,
        name_source_offset: None,
        name_source_size: 0,
        timestamp: None,
        weak: kind == "weak",
        upward: kind == "upward",
        reexport: kind == "reexport",
        delayed_init: false,
        current_version: None,
        compatibility_version: None,
        command_offset: command as u64,
        command_size: command_size as u64,
        valid: false,
    };
    if command_size < 24 {
        image
            .dylib_issues
            .push("Truncated dylib load command".into());
        return record;
    }
    let name_offset = match read_u32(bytes, command + 8, little) {
        Ok(value) => value as usize,
        Err(_) => {
            image
                .dylib_issues
                .push("Dylib name offset is truncated".into());
            return record;
        }
    };
    record.name_offset = Some(name_offset as u64);
    record.timestamp = read_u32(bytes, command + 12, little).ok();
    record.current_version = read_u32(bytes, command + 16, little).ok().map(version);
    record.compatibility_version = read_u32(bytes, command + 20, little).ok().map(version);
    let uses_flags = name_offset == 28
        && command_size >= 28
        && read_u32(bytes, command + 12, little).ok() == Some(0x1a74_1800);
    if uses_flags {
        record.encoding = "dylib_use_command";
        let flags = read_u32(bytes, command + 24, little).unwrap_or(0);
        record.weak |= flags & 0x1 != 0;
        record.reexport |= flags & 0x2 != 0;
        record.upward |= flags & 0x4 != 0;
        record.delayed_init = flags & 0x8 != 0;
    }
    let name_offset = if uses_flags { 28 } else { name_offset };
    if name_offset >= command_size {
        image
            .dylib_issues
            .push("Dylib name offset is outside the command".into());
        return record;
    }
    let Some(start) = command.checked_add(name_offset) else {
        image
            .dylib_issues
            .push("Dylib name offset overflowed".into());
        return record;
    };
    let Some(end) = command.checked_add(command_size) else {
        image
            .dylib_issues
            .push("Dylib command range overflowed".into());
        return record;
    };
    let Some(raw) = bytes.get(start..end) else {
        image
            .dylib_issues
            .push("Dylib command is outside the snapshot".into());
        return record;
    };
    let terminator = raw.iter().position(|byte| *byte == 0);
    let value_end = terminator.unwrap_or(raw.len());
    let raw_end = terminator.map_or(value_end, |index| index + 1);
    record.name_bytes = raw[..raw_end].to_vec();
    record.name_utf8_valid = std::str::from_utf8(&raw[..value_end]).is_ok();
    record.name = Some(String::from_utf8_lossy(&raw[..value_end]).into_owned());
    record.name_source_offset = Some(start as u64);
    record.name_source_size = value_end as u64;
    if !record.name_utf8_valid {
        image
            .dylib_issues
            .push("Dylib name is not valid UTF-8".into());
    }
    record.valid = terminator.is_some();
    if terminator.is_none() {
        image.dylib_issues.push("Dylib name is unterminated".into());
    }
    record
}

fn fixed_name_record(
    bytes: &[u8],
    offset: usize,
    size: usize,
) -> Result<(String, Vec<u8>, bool), Error> {
    let raw = bytes
        .get(offset..offset + size)
        .ok_or(Error::Malformed("Mach-O name is truncated"))?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let value = &raw[..end];
    Ok((
        String::from_utf8_lossy(value).into_owned(),
        value.to_vec(),
        std::str::from_utf8(value).is_ok(),
    ))
}

fn format_uuid(raw: &[u8]) -> String {
    let groups = [4, 2, 2, 2, 6];
    let mut cursor = 0;
    let mut value = String::with_capacity(36);
    for (index, width) in groups.into_iter().enumerate() {
        if index != 0 {
            value.push('-');
        }
        for byte in &raw[cursor..cursor + width] {
            value.push_str(&format!("{byte:02x}"));
        }
        cursor += width;
    }
    value
}

fn permissions(raw: u32) -> Permissions {
    Permissions {
        read: raw & 1 != 0,
        write: raw & 2 != 0,
        execute: raw & 4 != 0,
        raw: format!("0x{raw:x}"),
    }
}

fn section_flag_names(raw: u32) -> Vec<String> {
    let mut names = Vec::new();
    let section_type = raw & 0xff;
    let type_name = match section_type {
        0 => Some("S_REGULAR"),
        1 => Some("S_ZEROFILL"),
        2 => Some("S_CSTRING_LITERALS"),
        6 => Some("S_NON_LAZY_SYMBOL_POINTERS"),
        7 => Some("S_LAZY_SYMBOL_POINTERS"),
        8 => Some("S_SYMBOL_STUBS"),
        9 => Some("S_MOD_INIT_FUNC_POINTERS"),
        10 => Some("S_MOD_TERM_FUNC_POINTERS"),
        11 => Some("S_COALESCED"),
        13 => Some("S_INTERPOSING"),
        17 => Some("S_THREAD_LOCAL_REGULAR"),
        18 => Some("S_THREAD_LOCAL_ZEROFILL"),
        19 => Some("S_THREAD_LOCAL_VARIABLES"),
        20 => Some("S_THREAD_LOCAL_RELOCATION"),
        21 => Some("S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"),
        _ => None,
    };
    if let Some(name) = type_name {
        names.push(name.to_owned());
    }
    for (mask, name) in [
        (0x800u32, "S_ATTR_PURE_INSTRUCTIONS"),
        (0x400, "S_ATTR_NO_TOC"),
        (0x200, "S_ATTR_STRIP_STATIC_SYMS"),
        (0x100, "S_ATTR_NO_DEAD_STRIP"),
        (0x0400_0000, "S_ATTR_SELF_MODIFYING_CODE"),
        (0x0200_0000, "S_ATTR_DEBUG"),
        (0x8000_0000, "S_ATTR_LIVE_SUPPORT"),
    ] {
        if raw & mask != 0 {
            names.push(name.to_owned());
        }
    }
    names
}

fn platform_name(platform: u32) -> String {
    match platform {
        1 => "MACOS",
        2 => "IOS",
        3 => "TVOS",
        4 => "WATCHOS",
        5 => "BRIDGEOS",
        6 => "MACCATALYST",
        7 => "IOSSIMULATOR",
        8 => "TVOSSIMULATOR",
        9 => "WATCHOSSIMULATOR",
        10 => "DRIVERKIT",
        11 => "VISIONOS",
        12 => "VISIONOSSIMULATOR",
        13 => "FIRMWARE",
        14 => "SEPOS",
        15 => "MACOS_EXCLAVECORE",
        16 => "MACOS_EXCLAVEKIT",
        17 => "IOS_EXCLAVECORE",
        18 => "IOS_EXCLAVEKIT",
        19 => "TVOS_EXCLAVECORE",
        20 => "TVOS_EXCLAVEKIT",
        21 => "WATCHOS_EXCLAVECORE",
        22 => "WATCHOS_EXCLAVEKIT",
        23 => "VISIONOS_EXCLAVECORE",
        24 => "VISIONOS_EXCLAVEKIT",
        _ => return platform.to_string(),
    }
    .to_owned()
}

fn minimum_os_command_name(command: u32) -> &'static str {
    match command {
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x2f => "LC_VERSION_MIN_TVOS",
        _ => "LC_VERSION_MIN_WATCHOS",
    }
}

fn minimum_os_platform(command: u32, cpu: u32) -> u32 {
    let is_intel = matches!(cpu, 7 | 0x0100_0007);
    match command {
        0x24 => 1,
        0x25 if is_intel => 7,
        0x25 => 2,
        0x2f if cpu == 0x0100_0007 => 8,
        0x2f => 3,
        0x30 if is_intel => 9,
        _ => 4,
    }
}

fn minimum_os_platform_name(command: u32, platform: u32) -> &'static str {
    match platform {
        1 => "MACOSX",
        2 => "IPHONEOS",
        3 => "TVOS",
        4 => "WATCHOS",
        7 => "IOSSIMULATOR",
        8 => "TVOSSIMULATOR",
        9 => "WATCHOSSIMULATOR",
        _ => match command {
            0x24 => "MACOSX",
            0x25 => "IPHONEOS",
            0x2f => "TVOS",
            _ => "WATCHOS",
        },
    }
}

fn tool_name(tool: u32) -> String {
    match tool {
        1 => "CLANG",
        2 => "SWIFT",
        3 => "LD",
        4 => "LLD",
        1024 => "METAL",
        1025 => "AIRLLD",
        1026 => "AIRNT",
        1027 => "AIRNT_PLUGIN",
        1028 => "AIRPACK",
        1031 => "GPUARCHIVER",
        1032 => "METAL_FRAMEWORK",
        _ => return tool.to_string(),
    }
    .to_owned()
}

fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
        1 => "MH_OBJECT",
        2 => "MH_EXECUTE",
        3 => "MH_FVMLIB",
        4 => "MH_CORE",
        5 => "MH_PRELOAD",
        6 => "MH_DYLIB",
        7 => "MH_DYLINKER",
        8 => "MH_BUNDLE",
        9 => "MH_DYLIB_STUB",
        10 => "MH_DSYM",
        11 => "MH_KEXT_BUNDLE",
        _ => "MH_UNKNOWN",
    }
}

fn cpu_name(cpu: u32) -> &'static str {
    match cpu {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000c => "arm64",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        _ => "unknown",
    }
}

fn cpu_subtype_name(cpu: u32, subtype: u32) -> String {
    let base = subtype & 0x00ff_ffff;
    match (cpu, base) {
        (0x0100_000c, 2) => "ARM64E".to_owned(),
        (0x0100_0007, 8) => "X86_64H".to_owned(),
        (0x0100_0007, 3) => "X86_64_ALL".to_owned(),
        (12, 9) => "ARMV7".to_owned(),
        _ => format!("0x{subtype:x}"),
    }
}

fn data_in_code_kind_name(kind: u16) -> &'static str {
    match kind {
        1 => "DATA",
        2 => "JUMP_TABLE8",
        3 => "JUMP_TABLE16",
        4 => "JUMP_TABLE32",
        5 => "ABSOLUTE_SYMBOLS",
        _ => "UNKNOWN",
    }
}

fn export_flag_names(flags: u64) -> Vec<String> {
    [
        (0x04, "WEAK_DEFINITION"),
        (0x08, "REEXPORT"),
        (0x10, "STUB_AND_RESOLVER"),
    ]
    .into_iter()
    .filter_map(|(mask, name)| (flags & mask != 0).then_some(name.to_owned()))
    .collect()
}

fn header_flag_names(raw: u32) -> Vec<String> {
    [
        (0x1, "MH_NOUNDEFS"),
        (0x2, "MH_INCRLINK"),
        (0x4, "MH_DYLDLINK"),
        (0x8, "MH_BINDATLOAD"),
        (0x10, "MH_PREBOUND"),
        (0x20, "MH_SPLIT_SEGS"),
        (0x80, "MH_TWOLEVEL"),
        (0x200, "MH_NOMULTIDEFS"),
        (0x400, "MH_NOFIXPREBINDING"),
        (0x2000, "MH_SUBSECTIONS_VIA_SYMBOLS"),
        (0x8000, "MH_WEAK_DEFINES"),
        (0x10000, "MH_BINDS_TO_WEAK"),
        (0x20000, "MH_ALLOW_STACK_EXECUTION"),
        (0x40000, "MH_ROOT_SAFE"),
        (0x80000, "MH_SETUID_SAFE"),
        (0x200000, "MH_PIE"),
        (0x400000, "MH_DEAD_STRIPPABLE_DYLIB"),
        (0x2000000, "MH_APP_EXTENSION_SAFE"),
    ]
    .into_iter()
    .filter_map(|(mask, name)| (raw & mask != 0).then_some(name.to_owned()))
    .collect()
}

fn command_name(command: u32) -> &'static str {
    match command {
        0x1 => "LC_SEGMENT",
        0x2 => "LC_SYMTAB",
        0x4 => "LC_THREAD",
        0x5 => "LC_UNIXTHREAD",
        0xb => "LC_DYSYMTAB",
        0xc => "LC_LOAD_DYLIB",
        0xd => "LC_ID_DYLIB",
        0x12 => "LC_SUB_FRAMEWORK",
        0x13 => "LC_SUB_UMBRELLA",
        0x14 => "LC_SUB_CLIENT",
        0x15 => "LC_SUB_LIBRARY",
        0xe => "LC_LOAD_DYLINKER",
        0xf => "LC_ID_DYLINKER",
        0x10 => "LC_PREBOUND_DYLIB",
        0x11 => "LC_ROUTINES",
        0x16 => "LC_TWOLEVEL_HINTS",
        0x19 => "LC_SEGMENT_64",
        0x1b => "LC_UUID",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2c => "LC_ENCRYPTION_INFO_64",
        0x2d => "LC_LINKER_OPTION",
        0x2e => "LC_LINKER_OPTIMIZATION_HINTS",
        0x2f => "LC_VERSION_MIN_TVOS",
        0x30 => "LC_VERSION_MIN_WATCHOS",
        0x31 => "LC_NOTE",
        0x32 => "LC_BUILD_VERSION",
        0x8000_0018 => "LC_LOAD_WEAK_DYLIB",
        0x8000_001a => "LC_ROUTINES_64",
        0x8000_001c => "LC_RPATH",
        0x8000_001f => "LC_REEXPORT_DYLIB",
        0x8000_0022 => "LC_DYLD_INFO_ONLY",
        0x8000_0023 => "LC_LOAD_UPWARD_DYLIB",
        0x8000_0028 => "LC_MAIN",
        0x8000_0034 => "LC_DYLD_CHAINED_FIXUPS",
        0x8000_0033 => "LC_DYLD_EXPORTS_TRIE",
        0x8000_0035 => "LC_FILESET_ENTRY",
        _ => "LC_UNKNOWN",
    }
}

fn version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

fn source_version(value: u64) -> String {
    let major = value >> 40;
    let minor = (value >> 30) & 0x3ff;
    let patch = (value >> 20) & 0x3ff;
    let build = (value >> 10) & 0x3ff;
    let revision = value & 0x3ff;
    format!("{major}.{minor}.{patch}.{build}.{revision}")
}
fn word(bytes: &[u8], offset: usize, wide: bool, little: bool) -> Result<u64, Error> {
    if wide {
        read_u64(bytes, offset, little)
    } else {
        read_u32(bytes, offset, little).map(u64::from)
    }
}
fn read_be(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(Error::Malformed("Mach-O magic is truncated"))?;
    Ok(u32::from_be_bytes(raw.try_into().unwrap()))
}

fn read_be32_at(bytes: &[u8], offset: usize, end: usize) -> Result<u32, Error> {
    let field_end = offset
        .checked_add(4)
        .ok_or(Error::Malformed("Code signature field range overflowed"))?;
    if field_end > end {
        return Err(Error::Malformed("Code signature field is truncated"));
    }
    read_be(bytes, offset)
}

fn read_u32(bytes: &[u8], offset: usize, little: bool) -> Result<u32, Error> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(Error::Malformed("Mach-O field is truncated"))?;
    Ok(if little {
        u32::from_le_bytes(raw.try_into().unwrap())
    } else {
        u32::from_be_bytes(raw.try_into().unwrap())
    })
}

fn read_u16(bytes: &[u8], offset: usize, little: bool) -> Result<u16, Error> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(Error::Malformed("Mach-O field is truncated"))?;
    Ok(if little {
        u16::from_le_bytes(raw.try_into().unwrap())
    } else {
        u16::from_be_bytes(raw.try_into().unwrap())
    })
}
fn read_u64(bytes: &[u8], offset: usize, little: bool) -> Result<u64, Error> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(Error::Malformed("Mach-O field is truncated"))?;
    Ok(if little {
        u64::from_le_bytes(raw.try_into().unwrap())
    } else {
        u64::from_be_bytes(raw.try_into().unwrap())
    })
}
