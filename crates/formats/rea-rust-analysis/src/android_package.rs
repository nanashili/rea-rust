//! Bounded, read-only APK inspection. This parser owns ZIP entry framing and
//! the Android binary XML facts needed by the package contract; it never
//! executes dex code or verifies signatures.

use flate2::read::DeflateDecoder;
use serde::Serialize;
use std::{collections::BTreeSet, fmt, io::Read};

pub const MAX_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 100_000;

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    Resource(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(s) | Self::Unsupported(s) | Self::Resource(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Serialize)]
pub struct TextCoverage {
    pub status: &'static str,
    pub text: String,
    pub reported_total_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub package_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub max_sdk: Option<String>,
    pub min_sdk_value: Option<u32>,
    pub target_sdk_value: Option<u32>,
    pub max_sdk_value: Option<u32>,
    pub sdk_source_offset: Option<u32>,
    pub application_label: Option<String>,
    pub application_name: Option<String>,
    pub application_icon: Option<String>,
    pub application_round_icon: Option<String>,
    pub allow_backup: Option<bool>,
    pub extract_native_libs: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub debuggable: Option<bool>,
    pub permissions: Vec<String>,
    pub permission_details: Vec<PermissionDeclaration>,
    pub manifest: TextCoverage,
    pub class_count: usize,
    pub class_names: Vec<AndroidClassNameRow>,
    pub class_name_coverage: AndroidClassNameCoverage,
    pub resource_count: usize,
    pub resource_paths: Vec<String>,
    pub signature_verification: &'static str,
    pub signing_blocks: Vec<ApkSigningBlock>,
    pub resource_variants: Vec<ResourceVariant>,
    pub resource_string_pool: ResourceStringPool,
    pub resource_packages: Vec<ResourcePackage>,
    pub resource_pools: Vec<ResourcePool>,
    pub resource_entries: Vec<ResourceEntry>,
    pub dex: Vec<DexFacts>,
    pub components: Vec<Component>,
    pub features: Vec<UsesFeature>,
    pub supports_screens: SupportsScreens,
    pub queries: Option<QueryVisibility>,
    pub uses_libraries: Vec<LibraryDeclaration>,
    pub uses_native_libraries: Vec<LibraryDeclaration>,
    pub uses_configuration: Option<UsesConfiguration>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidClassNameRow {
    pub name: Option<String>,
    pub status: &'static str,
    pub dex_entry: String,
    pub dex_index: u32,
    pub source_offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidClassNameCoverage {
    pub status: &'static str,
    pub reported_total: usize,
    pub observed_rows: usize,
    pub unknown_rows: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsesFeature {
    pub name: Option<String>,
    pub gl_es_version: Option<String>,
    pub required: Option<bool>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SupportsScreens {
    pub small: Option<bool>,
    pub normal: Option<bool>,
    pub large: Option<bool>,
    pub xlarge: Option<bool>,
    pub any_density: Option<bool>,
    pub source_offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct QueryVisibility {
    pub packages: Vec<QueryPackage>,
    pub providers: Vec<QueryProvider>,
    pub intents: Vec<QueryIntent>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryPackage {
    pub name: Option<String>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryProvider {
    pub name: Option<String>,
    pub authorities: Option<String>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct QueryIntent {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub mime_types: Vec<String>,
    pub data: Vec<QueryData>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct QueryData {
    pub scheme: Option<String>,
    pub mime_type: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub path_prefix: Option<String>,
    pub path_pattern: Option<String>,
    pub path_advanced_pattern: Option<String>,
    pub path_suffix: Option<String>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibraryDeclaration {
    pub name: Option<String>,
    pub required: Option<bool>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PermissionDeclaration {
    pub tag: String,
    pub name: Option<String>,
    pub max_sdk_version: Option<String>,
    pub max_sdk_value: Option<u32>,
    pub uses_permission_flags: Option<String>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UsesConfiguration {
    pub req_keyboard_type: Option<String>,
    pub req_keyboard_type_value: Option<String>,
    pub req_navigation: Option<String>,
    pub req_navigation_value: Option<String>,
    pub req_touchscreen: Option<String>,
    pub req_touchscreen_value: Option<String>,
    pub req_five_way_nav: Option<bool>,
    pub req_hard_keyboard: Option<bool>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceVariant {
    pub resource_id: String,
    pub package_id: u32,
    pub package_name: Option<String>,
    pub package_name_source_offset: Option<u32>,
    pub type_id: u32,
    pub type_name: Option<String>,
    pub type_name_index: Option<u32>,
    pub type_pool_source_offset: Option<u32>,
    pub key_name: Option<String>,
    pub qualified_name: Option<String>,
    pub key_name_index: Option<u32>,
    pub key_pool_source_offset: Option<u32>,
    pub mapping_issue: Option<String>,
    pub configuration: String,
    pub configuration_facts: ResourceConfiguration,
    pub value: String,
    pub value_issue: Option<String>,
    pub value_string_pool_index: Option<u32>,
    pub value_string_pool_source_offset: Option<u32>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceStringPool {
    pub count: usize,
    pub strings: Vec<String>,
    pub encoding: String,
    pub entry_source_ranges: Vec<(u32, u32)>,
    pub invalid_utf16_indices: Vec<u32>,
    pub invalid_utf16_source_offsets: Vec<u32>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourcePackage {
    pub package_id: u32,
    pub name: Option<String>,
    pub name_issue: Option<String>,
    pub source_offset: u32,
    pub library_mappings: Vec<ResourceLibraryMapping>,
    pub staged_aliases: Vec<ResourceStagedAlias>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceLibraryMapping {
    pub package_id: Option<u32>,
    pub package_name: Option<String>,
    pub source_range: (u32, u32),
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceStagedAlias {
    pub staged_id_raw: Option<u32>,
    pub final_id_raw: Option<u32>,
    pub staged_id: Option<String>,
    pub final_id: Option<String>,
    pub source_range: (u32, u32),
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourcePool {
    pub package_id: u32,
    pub package_name: Option<String>,
    pub kind: String,
    pub count: usize,
    pub strings: Vec<String>,
    pub encoding: String,
    pub entry_source_ranges: Vec<(u32, u32)>,
    pub invalid_utf16_indices: Vec<u32>,
    pub invalid_utf16_source_offsets: Vec<u32>,
    pub source_offset: u32,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceEntry {
    pub resource_id: String,
    pub package_id: u32,
    pub package_name: Option<String>,
    pub package_name_source_offset: Option<u32>,
    pub type_id: u32,
    pub type_name: Option<String>,
    pub type_name_index: Option<u32>,
    pub type_pool_source_offset: Option<u32>,
    pub entry_index: u32,
    pub key_name: Option<String>,
    pub qualified_name: Option<String>,
    pub key_name_index: Option<u32>,
    pub key_pool_source_offset: Option<u32>,
    pub mapping_issue: Option<String>,
    pub value: Option<String>,
    pub source_offset: u32,
    pub issue: Option<String>,
    pub flags: Option<u16>,
    pub entry_size: Option<u16>,
    pub configuration: ResourceConfiguration,
    pub value_type: Option<u8>,
    pub value_data: Option<u32>,
    pub value_size: Option<u16>,
    pub value_res0: Option<u8>,
    pub decoded_value: Option<String>,
    pub string_pool_index: Option<u32>,
    pub string_pool_source_offset: Option<u32>,
    pub reference_id: Option<String>,
    pub parent_id: Option<u32>,
    pub complex_values: Vec<ResourceComplexValue>,
    pub offset_kind: Option<String>,
    pub offset_source_range: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceComplexValue {
    pub key: u32,
    pub key_resource_id: String,
    pub value_kind: String,
    pub value_type: Option<u8>,
    pub value_data: Option<u32>,
    pub value_size: Option<u16>,
    pub value_res0: Option<u8>,
    pub decoded_value: Option<String>,
    pub string_pool_index: Option<u32>,
    pub string_pool_source_offset: Option<u32>,
    pub reference_id: Option<String>,
    pub source_offset: u32,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceConfiguration {
    pub size: u32,
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
    pub locale: Option<String>,
    pub region: Option<String>,
    pub locale_script: Option<String>,
    pub locale_variant: Option<String>,
    pub locale_raw: Option<Vec<u8>>,
    pub density: Option<u16>,
    pub sdk: Option<u16>,
    /// The deprecated minor version component paired with `sdk` in version.
    /// Preserve it when present instead of folding it into the major SDK.
    pub sdk_minor: Option<u16>,
    pub orientation: Option<u8>,
    pub touchscreen: Option<u8>,
    pub keyboard: Option<u8>,
    pub navigation: Option<u8>,
    pub input_flags: Option<u8>,
    pub screen_width: Option<u16>,
    pub screen_height: Option<u16>,
    pub screen_layout: Option<u8>,
    pub ui_mode: Option<u8>,
    pub smallest_width: Option<u16>,
    pub screen_width_dp: Option<u16>,
    pub screen_height_dp: Option<u16>,
    /// The post-API-21 screen layout and color mode bytes from screenConfig2.
    ///
    /// Keep the raw values because individual bits have changed meaning across
    /// Android releases and callers may need to distinguish an unknown value
    /// from an absent qualifier.
    pub screen_layout_2: Option<u8>,
    pub color_mode: Option<u8>,
    pub source_offset: u32,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApkSigningBlock {
    pub id: u32,
    pub source_offset: u32,
    pub size: u64,
    pub signers: Vec<ApkSigner>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApkSigner {
    pub source_offset: u32,
    pub algorithms: Vec<u32>,
    pub certificate_ranges: Vec<(u32, u32)>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Component {
    pub kind: String,
    pub name: String,
    pub exported: Option<bool>,
    pub target_activity: Option<String>,
    pub enabled: Option<bool>,
    pub permission: Option<String>,
    pub process: Option<String>,
    pub launch_mode: Option<String>,
    pub theme: Option<String>,
    pub source_offset: u32,
    pub intent_filter_count: usize,
    pub intent_filters: Vec<IntentFilter>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub mime_types: Vec<String>,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DexFacts {
    pub entry: String,
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub methods: Vec<DexMethod>,
    pub classes: Vec<String>,
    pub referenced_methods: Vec<String>,
    pub class_definitions: Vec<DexClass>,
    pub method_code_offsets: Vec<u32>,
    pub code: Vec<DexMethodCode>,
    pub references: Vec<DexReferenceEdge>,
    pub annotations: Vec<DexAnnotationAssociation>,
    pub call_sites: Vec<DexCallSite>,
    pub method_handles: Vec<DexMethodHandle>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexCallSite {
    pub index: u32,
    pub source_offset: u32,
    pub values: Vec<DexEncodedValue>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexMethodHandle {
    pub index: u32,
    pub source_offset: u32,
    pub kind: String,
    pub member_index: u32,
    pub target: Option<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexAnnotationAssociation {
    pub owner: String,
    pub visibility: String,
    pub type_descriptor: Option<String>,
    pub elements: Vec<DexAnnotationElement>,
    pub source_offset: u32,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexAnnotationElement {
    pub name: Option<String>,
    pub source_offset: u32,
    pub value: DexEncodedValue,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum DexEncodedValue {
    Integer(i64),
    String(Option<String>),
    Type(Option<String>),
    Enum {
        index: u32,
        name: Option<String>,
        source_offset: u32,
    },
    Boolean(bool),
    Null,
    Array(Vec<DexEncodedValue>),
    Annotation {
        type_descriptor: Option<String>,
        elements: Vec<DexAnnotationElement>,
    },
    Unsupported {
        value_type: u8,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DexMethodCode {
    pub method_index: u32,
    pub code_offset: u32,
    pub registers_size: Option<u16>,
    pub ins_size: Option<u16>,
    pub outs_size: Option<u16>,
    pub insns_size: Option<u32>,
    pub debug_info_offset: Option<u32>,
    pub instructions: Vec<DexInstruction>,
    pub tries: Vec<DexTryBlock>,
    pub invokes: Vec<DexInvokeEdge>,
    pub strings: Vec<DexStringEdge>,
    pub classes: Vec<DexClassEdge>,
    pub fields: Vec<DexFieldEdge>,
    pub debug: Option<DexDebugInfo>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexInstruction {
    pub code_unit_offset: u32,
    pub source_offset: u32,
    pub opcode: u8,
    pub width: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexTryBlock {
    pub source_offset: u32,
    pub start_code_unit: u32,
    pub insn_count: u16,
    pub handler_offset: u16,
    pub handlers: Vec<DexExceptionHandler>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexExceptionHandler {
    pub source_offset: u32,
    pub type_index: Option<u32>,
    pub type_descriptor: Option<String>,
    pub address: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DexDebugInfo {
    pub line_start: i32,
    pub parameters: Vec<Option<String>>,
    pub lines: Vec<DexDebugLine>,
    pub locals: Vec<DexDebugLocal>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexDebugLine {
    pub code_unit_offset: u32,
    pub line: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexDebugLocal {
    pub register: u32,
    pub name: Option<String>,
    pub local_type: Option<String>,
    pub signature: Option<String>,
    pub start_code_unit: u32,
    pub end_code_unit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexInvokeEdge {
    pub code_unit_offset: u32,
    pub method_index: u32,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexStringEdge {
    pub code_unit_offset: u32,
    pub string_index: u32,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexClassEdge {
    pub code_unit_offset: u32,
    pub type_index: u32,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexFieldEdge {
    pub code_unit_offset: u32,
    pub field_index: u32,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexReferenceEdge {
    pub dex_entry: String,
    pub caller_method_index: u32,
    pub caller: Option<String>,
    pub kind: &'static str,
    pub target_index: u32,
    pub target: Option<String>,
    pub status: &'static str,
    pub code_unit_offset: u32,
    pub source_offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexMethod {
    pub class_descriptor: String,
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexClass {
    pub descriptor: String,
    pub source_offset: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<DexField>,
    pub methods: Vec<DexDeclaredMethod>,
    pub static_values: Vec<DexStaticFieldValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexStaticFieldValue {
    pub field_index: u32,
    pub source_offset: u32,
    pub value: DexEncodedValue,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexField {
    pub index: u32,
    pub name: String,
    pub field_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexDeclaredMethod {
    pub index: u32,
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug)]
struct Entry<'a> {
    name: &'a str,
    method: u16,
    compressed: &'a [u8],
    size: usize,
}

/// Inspect an APK byte snapshot. Entry decompression and manifest decoding are bounded.
pub fn read(bytes: &[u8]) -> Result<Report, Error> {
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(Error::Resource("APK exceeds the maximum package size"));
    }
    let entries = entries(bytes)?;
    let manifest = entries
        .iter()
        .find(|e| e.name == "AndroidManifest.xml")
        .ok_or(Error::Malformed("APK does not contain AndroidManifest.xml"))?;
    let manifest_bytes = inflate(manifest)?;
    let resources = entries
        .iter()
        .find(|entry| entry.name == "resources.arsc")
        .map(inflate)
        .transpose()?;
    let resource_table = resources.as_deref().map(parse_resource_table).transpose()?;
    let parsed =
        resolve_manifest_resources(parse_manifest(&manifest_bytes)?, resource_table.as_ref());
    let (signing_blocks, signing_issue) = match parse_apk_signing_block(bytes) {
        Ok(blocks) => (blocks, None),
        Err(issue) => (Vec::new(), Some(issue)),
    };
    let resource_paths = apk_resource_paths(&entries);
    let resource_count = resource_count(resource_table.as_ref(), &resource_paths);
    let mut class_count = 0usize;
    let mut dex_facts = Vec::new();
    for entry in &entries {
        if entry.name.ends_with(".dex") {
            let dex = inflate(entry)?;
            if dex.len() >= 0x64 && &dex[..4] == b"dex\n" {
                class_count = class_count.saturating_add(u32::from_le_bytes(
                    dex[0x60..0x64].try_into().unwrap(),
                ) as usize);
                dex_facts.push(parse_dex(entry.name, &dex)?);
            }
        }
    }
    let mut limitations = vec![
        "APK bytes and entries are inspected without executing dex code or native libraries.".into(),
        "Signature verification is not performed.".into(),
        "Class counts come from dex headers and resource counts from res/ ZIP entries; neither proves runtime reachability.".into(),
    ];
    if parsed.binary {
        limitations.push("Manifest text is reconstructed from Android binary XML; formatting and comments are not preserved.".into());
    }
    if let Some(issue) = signing_issue {
        limitations.push(format!(
            "APK Signing Block metadata is unavailable: {issue}"
        ));
    }
    let (class_names, class_name_coverage) = android_class_name_projection(&dex_facts, class_count);
    Ok(Report {
        package_name: parsed.package_name,
        version_name: parsed.version_name,
        version_code: parsed.version_code,
        min_sdk: parsed.min_sdk,
        target_sdk: parsed.target_sdk,
        max_sdk: parsed.max_sdk,
        min_sdk_value: parsed.min_sdk_value,
        target_sdk_value: parsed.target_sdk_value,
        max_sdk_value: parsed.max_sdk_value,
        sdk_source_offset: parsed.sdk_source_offset,
        application_label: parsed.application_label,
        application_name: parsed.application_name,
        application_icon: parsed.application_icon,
        application_round_icon: parsed.application_round_icon,
        allow_backup: parsed.allow_backup,
        extract_native_libs: parsed.extract_native_libs,
        uses_cleartext_traffic: parsed.uses_cleartext_traffic,
        debuggable: parsed.debuggable,
        permissions: parsed.permissions,
        permission_details: parsed.permission_details,
        manifest: TextCoverage {
            status: "complete",
            text: parsed.text,
            reported_total_bytes: Some(manifest_bytes.len()),
        },
        class_count,
        class_names,
        class_name_coverage,
        resource_count,
        resource_paths,
        signature_verification: "not_performed",
        signing_blocks,
        resource_variants: resource_table
            .as_ref()
            .map(|table| table.variants.clone())
            .unwrap_or_default(),
        resource_string_pool: resource_table
            .as_ref()
            .map(|table| table.string_pool.clone())
            .unwrap_or_default(),
        resource_packages: resource_table
            .as_ref()
            .map(|table| table.packages.clone())
            .unwrap_or_default(),
        resource_pools: resource_table
            .as_ref()
            .map(|table| table.pools.clone())
            .unwrap_or_default(),
        resource_entries: resource_table
            .as_ref()
            .map(|table| table.entries.clone())
            .unwrap_or_default(),
        dex: dex_facts,
        components: parsed.components,
        features: parsed.features,
        supports_screens: parsed.supports_screens,
        queries: parsed.queries,
        uses_libraries: parsed.uses_libraries,
        uses_native_libraries: parsed.uses_native_libraries,
        uses_configuration: parsed.uses_configuration,
        limitations,
    })
}

fn resource_count(table: Option<&ResourceTable>, resource_paths: &[String]) -> usize {
    table
        .map(|table| table.entries.len())
        .unwrap_or_else(|| resource_paths.len())
}

fn parse_apk_signing_block(bytes: &[u8]) -> Result<Vec<ApkSigningBlock>, Error> {
    let search_start = bytes.len().saturating_sub(65_557);
    let eocd = (search_start..bytes.len().saturating_sub(21))
        .rev()
        .find(|offset| bytes.get(*offset..*offset + 4) == Some(b"PK\x05\x06"))
        .ok_or(Error::Malformed(
            "APK end-of-central-directory record is missing",
        ))?;
    let central_offset =
        u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    if central_offset < 24 || central_offset > bytes.len() {
        return Err(Error::Malformed("APK central-directory offset is invalid"));
    }
    let footer = central_offset - 24;
    if &bytes[footer + 8..footer + 24] != b"APK Sig Block 42" {
        return Ok(Vec::new());
    }
    let size = u64::from_le_bytes(bytes[footer..footer + 8].try_into().unwrap());
    let total = size
        .checked_add(8)
        .ok_or(Error::Resource("APK Signing Block size overflows"))?;
    let start = (central_offset as u64)
        .checked_sub(total)
        .ok_or(Error::Malformed("APK Signing Block start underflows"))? as usize;
    if start + 8 > footer || u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap()) != size
    {
        return Err(Error::Malformed(
            "APK Signing Block size footer does not match",
        ));
    }
    let mut cursor = start + 8;
    let mut blocks = Vec::new();
    while cursor < footer {
        if cursor + 8 > footer {
            return Err(Error::Malformed(
                "APK Signing Block pair length is truncated",
            ));
        }
        let pair_size = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        let pair_end = cursor
            .checked_add(8)
            .and_then(|value| value.checked_add(pair_size))
            .ok_or(Error::Resource("APK Signing Block pair size overflows"))?;
        if pair_size < 4 || pair_end > footer {
            return Err(Error::Malformed("APK Signing Block pair is truncated"));
        }
        let id = u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
        let value_start = cursor + 12;
        let value_end = pair_end;
        let signers = if id == 0x7109_871a || id == 0xf053_68c0 {
            parse_signers(&bytes[value_start..value_end], value_start as u32)
        } else {
            Vec::new()
        };
        blocks.push(ApkSigningBlock {
            id,
            source_offset: value_start as u32,
            size: pair_size as u64,
            signers,
            issues: Vec::new(),
        });
        cursor = pair_end;
    }
    Ok(blocks)
}

fn parse_signers(bytes: &[u8], base: u32) -> Vec<ApkSigner> {
    let Ok((_, end)) = length_prefixed(bytes, 0) else {
        return Vec::new();
    };
    let mut cursor = 4;
    let mut signers = Vec::new();
    while cursor < end {
        let signer_offset = cursor;
        let Ok((signer_start, signer_end)) = length_prefixed(bytes, cursor) else {
            break;
        };
        cursor = signer_end;
        let signer = &bytes[signer_start..signer_end];
        let mut at = 0;
        let Ok((signed_start, signed_end)) = length_prefixed(signer, at) else {
            continue;
        };
        at = signed_end;
        let mut algorithms = Vec::new();
        let mut certificate_ranges = Vec::new();
        if let Ok((_, digest_end)) = length_prefixed(signer, signed_start) {
            if let Ok((certs_start, certs_end)) = length_prefixed(signer, digest_end) {
                let mut cert_cursor = certs_start;
                while cert_cursor < certs_end {
                    let Ok((cert_start, cert_end)) = length_prefixed(signer, cert_cursor) else {
                        break;
                    };
                    certificate_ranges.push((
                        base + signer_offset as u32 + cert_start as u32,
                        (cert_end - cert_start) as u32,
                    ));
                    cert_cursor = cert_end;
                }
            }
        }
        if let Ok((_, signatures_end)) = length_prefixed(signer, at) {
            let mut sig_cursor = at + 4;
            while sig_cursor < signatures_end {
                let Ok((sig_start, sig_end)) = length_prefixed(signer, sig_cursor) else {
                    break;
                };
                if sig_end - sig_start >= 4 {
                    algorithms.push(u32::from_le_bytes(
                        signer[sig_start..sig_start + 4].try_into().unwrap(),
                    ));
                }
                sig_cursor = sig_end;
            }
        }
        signers.push(ApkSigner {
            source_offset: base + signer_offset as u32,
            algorithms,
            certificate_ranges,
            issues: Vec::new(),
        });
    }
    signers
}

fn length_prefixed(bytes: &[u8], offset: usize) -> Result<(usize, usize), Error> {
    let length = u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Malformed("length-prefixed value is truncated"))?
            .try_into()
            .unwrap(),
    ) as usize;
    let start = offset + 4;
    let end = start
        .checked_add(length)
        .ok_or(Error::Resource("length-prefixed value overflows"))?;
    if end > bytes.len() {
        return Err(Error::Malformed("length-prefixed value is truncated"));
    }
    Ok((start, end))
}

fn entries(bytes: &[u8]) -> Result<Vec<Entry<'_>>, Error> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset.checked_add(30).is_some_and(|n| n <= bytes.len()) {
        if &bytes[offset..offset + 4] != b"PK\x03\x04" {
            break;
        }
        if out.len() >= MAX_ENTRIES {
            return Err(Error::Resource("APK entry count exceeds the maximum"));
        }
        let method = u16::from_le_bytes(bytes[offset + 8..offset + 10].try_into().unwrap());
        let compressed_size =
            u32::from_le_bytes(bytes[offset + 18..offset + 22].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(bytes[offset + 22..offset + 26].try_into().unwrap()) as usize;
        let name_len =
            u16::from_le_bytes(bytes[offset + 26..offset + 28].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(bytes[offset + 28..offset + 30].try_into().unwrap()) as usize;
        if size > MAX_ENTRY_BYTES {
            return Err(Error::Resource("APK entry exceeds the maximum size"));
        }
        let start = offset
            .checked_add(30 + name_len + extra_len)
            .ok_or(Error::Malformed("APK entry offset overflow"))?;
        let end = start
            .checked_add(compressed_size)
            .ok_or(Error::Malformed("APK entry data overflow"))?;
        if end > bytes.len() {
            return Err(Error::Malformed("APK entry is truncated"));
        }
        let name = std::str::from_utf8(&bytes[offset + 30..offset + 30 + name_len])
            .map_err(|_| Error::Malformed("APK entry name is not UTF-8"))?;
        out.push(Entry {
            name,
            method,
            compressed: &bytes[start..end],
            size,
        });
        offset = end;
    }
    if out.is_empty() {
        return Err(Error::Malformed("APK contains no local file entries"));
    }
    Ok(out)
}

fn apk_resource_paths(entries: &[Entry<'_>]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry.name.starts_with("res/") && !entry.name.ends_with('/'))
        .map(|entry| entry.name.to_owned())
        .collect()
}

fn inflate(entry: &Entry<'_>) -> Result<Vec<u8>, Error> {
    if entry.size > MAX_ENTRY_BYTES {
        return Err(Error::Resource("APK entry exceeds the maximum size"));
    }
    let mut output = Vec::with_capacity(entry.size.min(1024 * 1024));
    match entry.method {
        0 => output.extend_from_slice(entry.compressed),
        8 => {
            DeflateDecoder::new(entry.compressed)
                .read_to_end(&mut output)
                .map_err(|_| Error::Malformed("APK deflate stream is invalid"))?;
        }
        _ => return Err(Error::Unsupported("APK compression method is unsupported")),
    }
    if output.len() > MAX_ENTRY_BYTES || output.len() != entry.size {
        return Err(Error::Malformed(
            "APK entry size does not match its payload",
        ));
    }
    Ok(output)
}

fn parse_dex(entry: &str, bytes: &[u8]) -> Result<DexFacts, Error> {
    if bytes.len() < 0x70 || &bytes[..4] != b"dex\n" {
        return Err(Error::Malformed("DEX header is truncated"));
    }
    let string_count = read_u32_at(bytes, 0x38)? as usize;
    let string_off = read_u32_at(bytes, 0x3c)? as usize;
    let type_count = read_u32_at(bytes, 0x40)? as usize;
    let type_off = read_u32_at(bytes, 0x44)? as usize;
    let method_count = read_u32_at(bytes, 0x58)? as usize;
    let method_off = read_u32_at(bytes, 0x5c)? as usize;
    let field_count = read_u32_at(bytes, 0x50)? as usize;
    let field_off = read_u32_at(bytes, 0x54)? as usize;
    let map_off = read_u32_at(bytes, 0x34)? as usize;
    let class_count = read_u32_at(bytes, 0x60)? as usize;
    let class_off = read_u32_at(bytes, 0x64)? as usize;
    let limit = |count: usize| count.min(100_000);
    let table_end = |offset: usize, count: usize| {
        offset
            .checked_add(
                count
                    .checked_mul(4)
                    .ok_or(Error::Resource("DEX table size overflow"))?,
            )
            .ok_or(Error::Resource("DEX table size overflow"))
    };
    let strings = (0..limit(string_count))
        .map(|i| read_u32_at(bytes, string_off + i * 4))
        .collect::<Result<Vec<_>, _>>()?;
    let proto_count = read_u32_at(bytes, 0x48)? as usize;
    let proto_off = read_u32_at(bytes, 0x4c)? as usize;
    if proto_off
        .checked_add(
            proto_count
                .checked_mul(12)
                .ok_or(Error::Resource("DEX prototype table size overflow"))?,
        )
        .ok_or(Error::Resource("DEX prototype table size overflow"))?
        > bytes.len()
    {
        return Err(Error::Malformed("DEX prototype table is truncated"));
    }
    if table_end(string_off, string_count)? > bytes.len() {
        return Err(Error::Malformed("DEX string table is truncated"));
    }
    let string_values = strings
        .iter()
        .map(|offset| dex_string(bytes, *offset))
        .collect::<Result<Vec<_>, _>>()?;
    if table_end(type_off, type_count)? > bytes.len() {
        return Err(Error::Malformed("DEX type table is truncated"));
    }
    let types = (0..limit(type_count))
        .map(|i| {
            read_u32_at(bytes, type_off + i * 4).map(|index| {
                string_values
                    .get(index as usize)
                    .cloned()
                    .unwrap_or_default()
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if table_end(method_off, method_count * 2)? > bytes.len() {
        return Err(Error::Malformed("DEX method table is truncated"));
    }
    let mut methods = Vec::new();
    let mut referenced_methods = Vec::new();
    for i in 0..limit(method_count) {
        let at = method_off + i * 8;
        let class = read_u16_at(bytes, at)? as usize;
        let proto = read_u16_at(bytes, at + 2)? as usize;
        let name = read_u32_at(bytes, at + 4)? as usize;
        let class_descriptor = types.get(class).cloned().unwrap_or_default();
        let method_name = string_values.get(name).cloned().unwrap_or_default();
        let descriptor = proto_descriptor(bytes, &types, proto)?;
        referenced_methods.push(format!("{class_descriptor}->{method_name}{descriptor}"));
        methods.push(DexMethod {
            class_descriptor,
            name: method_name,
            descriptor,
        });
    }
    if table_end(field_off, field_count * 2)? > bytes.len() {
        return Err(Error::Malformed("DEX field table is truncated"));
    }
    let fields = (0..limit(field_count))
        .map(|i| {
            let at = field_off + i * 8;
            let class = read_u16_at(bytes, at)? as usize;
            let ty = read_u16_at(bytes, at + 2)? as usize;
            let name = read_u32_at(bytes, at + 4)? as usize;
            Ok((
                types.get(class).cloned().unwrap_or_default(),
                DexField {
                    index: i as u32,
                    name: string_values.get(name).cloned().unwrap_or_default(),
                    field_type: types.get(ty).cloned().unwrap_or_default(),
                },
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let (call_sites, method_handles) =
        parse_dex_link_sections(bytes, map_off, &string_values, &types, &fields, &methods);
    if table_end(class_off, class_count * 8)? > bytes.len() {
        return Err(Error::Malformed("DEX class table is truncated"));
    }
    let classes = (0..limit(class_count))
        .map(|i| {
            read_u32_at(bytes, class_off + i * 32)
                .map(|index| types.get(index as usize).cloned().unwrap_or_default())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut class_definitions = Vec::new();
    let mut all_code_offsets = Vec::new();
    let mut code = Vec::new();
    let mut references = Vec::new();
    let mut annotations = Vec::new();
    for i in 0..limit(class_count) {
        let at = class_off + i * 32;
        let class_idx = read_u32_at(bytes, at)? as usize;
        let superclass_idx = read_u32_at(bytes, at + 8)? as usize;
        let interfaces_off = read_u32_at(bytes, at + 12)? as usize;
        let class_data_off = read_u32_at(bytes, at + 24)? as usize;
        let static_values_off = read_u32_at(bytes, at + 28)? as usize;
        let annotations_off = read_u32_at(bytes, at + 20)? as usize;
        let interfaces = read_type_list(bytes, interfaces_off, &types)?;
        let (field_indexes, method_indexes, code_offsets, static_field_indexes) =
            read_class_data(bytes, class_data_off)?;
        all_code_offsets.extend(code_offsets.iter().copied());
        for (method_index, code_offset) in method_indexes.iter().zip(code_offsets.iter()) {
            if *code_offset != 0 {
                let decoded = decode_code_item_with_references(
                    bytes,
                    *code_offset,
                    *method_index,
                    &string_values,
                    &types,
                    &fields,
                    &methods,
                );
                references.extend(reference_edges_for_code(entry, &decoded, &methods));
                code.push(decoded);
            }
        }
        if annotations_off != 0 {
            annotations.extend(parse_annotation_directory(
                bytes,
                annotations_off,
                types.as_slice(),
                &string_values,
                &fields,
                &methods,
            ));
        }
        let static_values = parse_static_values(
            bytes,
            static_values_off,
            &static_field_indexes,
            &string_values,
            &types,
        );
        class_definitions.push(DexClass {
            descriptor: types.get(class_idx).cloned().unwrap_or_default(),
            source_offset: at as u32,
            superclass: (superclass_idx != u32::MAX as usize)
                .then(|| types.get(superclass_idx).cloned().unwrap_or_default()),
            interfaces,
            fields: field_indexes
                .into_iter()
                .filter_map(|index| fields.get(index as usize).map(|(_, field)| field.clone()))
                .collect(),
            methods: method_indexes
                .into_iter()
                .filter_map(|index| {
                    methods.get(index as usize).map(|method| DexDeclaredMethod {
                        index,
                        name: method.name.clone(),
                        descriptor: method.descriptor.clone(),
                    })
                })
                .collect(),
            static_values,
        });
    }
    Ok(DexFacts {
        entry: entry.to_owned(),
        strings: string_values.into_iter().take(100_000).collect(),
        types,
        methods,
        classes,
        referenced_methods,
        class_definitions,
        method_code_offsets: all_code_offsets,
        code,
        references,
        annotations,
        call_sites,
        method_handles,
        truncated: string_count > 100_000
            || type_count > 100_000
            || method_count > 100_000
            || class_count > 100_000,
    })
}
fn dex_string(bytes: &[u8], offset: u32) -> Result<String, Error> {
    let mut cursor = offset as usize;
    let _ = read_uleb(bytes, &mut cursor)?;
    let end = bytes[cursor..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|n| cursor + n)
        .ok_or(Error::Malformed("DEX string is unterminated"))?;
    Ok(String::from_utf8_lossy(&bytes[cursor..end]).into_owned())
}

fn android_class_name_projection(
    dex_facts: &[DexFacts],
    reported_total: usize,
) -> (Vec<AndroidClassNameRow>, AndroidClassNameCoverage) {
    let mut rows = Vec::new();
    let mut unknown_rows = 0usize;
    let mut truncated = false;

    for dex in dex_facts {
        truncated |= dex.truncated;
        for (dex_index, name) in dex.classes.iter().enumerate() {
            let name = (!name.is_empty()).then(|| name.clone());
            let status = if name.is_some() { "known" } else { "unknown" };
            if name.is_none() {
                unknown_rows = unknown_rows.saturating_add(1);
            }
            rows.push(AndroidClassNameRow {
                name,
                status,
                dex_entry: dex.entry.clone(),
                dex_index: dex_index as u32,
                source_offset: dex
                    .class_definitions
                    .get(dex_index)
                    .map(|class| class.source_offset),
            });
        }
    }

    let status = if !truncated && rows.len() == reported_total && unknown_rows == 0 {
        "complete"
    } else {
        "partial"
    };
    let observed_rows = rows.len();
    let coverage = AndroidClassNameCoverage {
        status,
        reported_total,
        observed_rows,
        unknown_rows,
    };
    (rows, coverage)
}

fn read_type_list(bytes: &[u8], offset: usize, types: &[String]) -> Result<Vec<String>, Error> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let count = read_u32_at(bytes, offset)? as usize;
    if count > 100_000 {
        return Err(Error::Resource("DEX interface count exceeds the maximum"));
    }
    (0..count)
        .map(|i| {
            read_u16_at(bytes, offset + 4 + i * 2)
                .map(|index| types.get(index as usize).cloned().unwrap_or_default())
        })
        .collect()
}
fn read_class_data(
    bytes: &[u8],
    offset: usize,
) -> Result<(Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>), Error> {
    if offset == 0 {
        return Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new()));
    }
    let mut cursor = offset;
    let static_field_count = read_uleb(bytes, &mut cursor)? as usize;
    let instance_fields = read_uleb(bytes, &mut cursor)? as usize;
    let direct_methods = read_uleb(bytes, &mut cursor)? as usize;
    let virtual_methods = read_uleb(bytes, &mut cursor)? as usize;
    let total_fields = static_field_count
        .checked_add(instance_fields)
        .ok_or(Error::Resource("DEX field count overflow"))?;
    let total_methods = direct_methods
        .checked_add(virtual_methods)
        .ok_or(Error::Resource("DEX method count overflow"))?;
    if total_fields > 100_000 || total_methods > 100_000 {
        return Err(Error::Resource("DEX class-data count exceeds the maximum"));
    }
    let mut fields = Vec::with_capacity(total_fields);
    let mut static_fields = Vec::with_capacity(static_field_count);
    let mut index = 0u32;
    for field_position in 0..total_fields {
        index = index
            .checked_add(read_uleb(bytes, &mut cursor)?)
            .ok_or(Error::Malformed("DEX field index overflow"))?;
        let _ = read_uleb(bytes, &mut cursor)?;
        fields.push(index);
        if field_position < static_field_count {
            static_fields.push(index);
        }
    }
    let mut methods = Vec::with_capacity(total_methods);
    let mut code_offsets = Vec::with_capacity(total_methods);
    let mut method_index = 0u32;
    for _ in 0..total_methods {
        method_index = method_index
            .checked_add(read_uleb(bytes, &mut cursor)?)
            .ok_or(Error::Malformed("DEX method index overflow"))?;
        let _ = read_uleb(bytes, &mut cursor)?;
        code_offsets.push(read_uleb(bytes, &mut cursor)?);
        methods.push(method_index);
    }
    Ok((fields, methods, code_offsets, static_fields))
}

fn decode_code_item_with_references(
    bytes: &[u8],
    code_offset: u32,
    method_index: u32,
    string_values: &[String],
    types: &[String],
    fields: &[(String, DexField)],
    methods: &[DexMethod],
) -> DexMethodCode {
    let mut result = DexMethodCode {
        method_index,
        code_offset,
        ..DexMethodCode::default()
    };
    let header = code_offset as usize;
    let read_header_u16 = |offset: usize| read_u16_at(bytes, header + offset).ok();
    result.registers_size = read_header_u16(0);
    result.ins_size = read_header_u16(2);
    result.outs_size = read_header_u16(4);
    let tries_size = read_header_u16(6).unwrap_or(0);
    if result.registers_size.is_none()
        || result.ins_size.is_none()
        || result.outs_size.is_none()
        || read_header_u16(6).is_none()
    {
        result
            .issues
            .push("code_item header sizes are truncated".into());
    }
    let Some(insns_size_offset) = header.checked_add(12) else {
        result
            .issues
            .push("code_item header offset overflows".into());
        return result;
    };
    let Ok(insns_size) = read_u32_at(bytes, insns_size_offset) else {
        result.issues.push("code_item header is truncated".into());
        return result;
    };
    result.insns_size = Some(insns_size);
    let debug_info_offset = match read_u32_at(bytes, header + 8) {
        Ok(offset) => offset,
        Err(_) => {
            result
                .issues
                .push("code_item debug-info offset is truncated".into());
            0
        }
    };
    result.debug_info_offset = (debug_info_offset != 0).then_some(debug_info_offset);
    let insns_size = insns_size as usize;
    if insns_size > 1_000_000 {
        result
            .issues
            .push("code_item instruction count exceeds the maximum".into());
        return result;
    }
    let Some(insns_start) = header.checked_add(16) else {
        result
            .issues
            .push("code_item instruction offset overflows".into());
        return result;
    };
    let Some(insns_bytes) = insns_size.checked_mul(2) else {
        result
            .issues
            .push("code_item instruction size overflows".into());
        return result;
    };
    let Some(insns_end) = insns_start.checked_add(insns_bytes) else {
        result
            .issues
            .push("code_item instruction end overflows".into());
        return result;
    };
    if insns_end > bytes.len() {
        result
            .issues
            .push("code_item instructions are truncated".into());
        return result;
    }

    let mut cursor = 0usize;
    while cursor < insns_size {
        let unit = u16::from_le_bytes(
            bytes[insns_start + cursor * 2..insns_start + cursor * 2 + 2]
                .try_into()
                .unwrap(),
        );
        let opcode = unit & 0xff;
        let width = match opcode {
            0x28 => 1,
            0x29 | 0x32..=0x3d => 2,
            0x2a => 3,
            0x1a | 0x1c | 0x1f | 0x22 => 2,
            0x1b => 3,
            0x52..=0x6d | 0x6e..=0x72 | 0x74..=0x78 => 3,
            0xfa | 0xfb => 4,
            _ => 1,
        };
        if cursor + width > insns_size {
            result.issues.push(format!(
                "opcode 0x{opcode:02x} at code-unit offset {cursor} is truncated"
            ));
            break;
        }
        let branch_delta = match opcode {
            0x28 => Some((unit as u8 as i8) as i32),
            0x29 | 0x32..=0x3d => Some(i16::from_le_bytes(
                bytes[insns_start + (cursor + 1) * 2..insns_start + (cursor + 2) * 2]
                    .try_into()
                    .unwrap(),
            ) as i32),
            0x2a => Some(i32::from_le_bytes(
                bytes[insns_start + (cursor + 1) * 2..insns_start + (cursor + 3) * 2]
                    .try_into()
                    .unwrap(),
            )),
            _ => None,
        };
        if let Some(delta) = branch_delta {
            let target = cursor as i64 + delta as i64;
            if target < 0 || target >= insns_size as i64 {
                result.issues.push(format!(
                    "branch opcode 0x{opcode:02x} at code-unit offset {cursor} targets outside code"
                ));
            }
        }
        result.instructions.push(DexInstruction {
            code_unit_offset: cursor as u32,
            source_offset: code_offset
                .saturating_add(16)
                .saturating_add((cursor as u32).saturating_mul(2)),
            opcode: opcode as u8,
            width: width as u16,
        });
        match opcode {
            0x1a => {
                let index = u16::from_le_bytes(
                    bytes[insns_start + (cursor + 1) * 2..insns_start + (cursor + 2) * 2]
                        .try_into()
                        .unwrap(),
                ) as u32;
                result.strings.push(DexStringEdge {
                    code_unit_offset: cursor as u32,
                    string_index: index,
                    value: string_values.get(index as usize).cloned(),
                });
            }
            0x1b => {
                let index = u32::from_le_bytes(
                    bytes[insns_start + (cursor + 1) * 2..insns_start + (cursor + 3) * 2]
                        .try_into()
                        .unwrap(),
                );
                result.strings.push(DexStringEdge {
                    code_unit_offset: cursor as u32,
                    string_index: index,
                    value: string_values.get(index as usize).cloned(),
                });
            }
            0x1c | 0x1f | 0x22 => {
                let index = u16::from_le_bytes(
                    bytes[insns_start + (cursor + 1) * 2..insns_start + (cursor + 2) * 2]
                        .try_into()
                        .unwrap(),
                ) as u32;
                result.classes.push(DexClassEdge {
                    code_unit_offset: cursor as u32,
                    type_index: index,
                    target: types.get(index as usize).cloned(),
                });
            }
            0x52..=0x6d => {
                let index = u16::from_le_bytes(
                    bytes[insns_start + (cursor + 1) * 2..insns_start + (cursor + 2) * 2]
                        .try_into()
                        .unwrap(),
                ) as u32;
                result.fields.push(DexFieldEdge {
                    code_unit_offset: cursor as u32,
                    field_index: index,
                    target: fields.get(index as usize).map(|(owner, field)| {
                        format!("{owner}->{}:{}", field.name, field.field_type)
                    }),
                });
            }
            0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb => {
                let index = u16::from_le_bytes(
                    bytes[insns_start + (cursor + 1) * 2..insns_start + (cursor + 2) * 2]
                        .try_into()
                        .unwrap(),
                ) as u32;
                result.invokes.push(DexInvokeEdge {
                    code_unit_offset: cursor as u32,
                    method_index: index,
                    target: methods.get(index as usize).map(|method| {
                        format!(
                            "{}->{}{}",
                            method.class_descriptor, method.name, method.descriptor
                        )
                    }),
                });
            }
            _ => {}
        }
        cursor += width;
    }
    if tries_size != 0 {
        let (tries, issues) =
            decode_try_blocks(bytes, insns_end, insns_size as u32, tries_size, types);
        result.tries = tries;
        result.issues.extend(issues);
    }
    if debug_info_offset != 0 {
        let (debug, issues) = decode_debug_info(bytes, debug_info_offset, string_values);
        result.debug = Some(debug);
        result.issues.extend(issues);
    }
    result
}

fn reference_edges_for_code(
    dex_entry: &str,
    code: &DexMethodCode,
    methods: &[DexMethod],
) -> Vec<DexReferenceEdge> {
    let caller = methods.get(code.method_index as usize).map(|method| {
        format!(
            "{}->{}{}",
            method.class_descriptor, method.name, method.descriptor
        )
    });
    let source_offset = |code_unit_offset: u32| {
        code.code_offset
            .saturating_add(16)
            .saturating_add(code_unit_offset.saturating_mul(2))
    };
    let mut references = Vec::new();
    for invoke in &code.invokes {
        references.push(DexReferenceEdge {
            dex_entry: dex_entry.to_owned(),
            caller_method_index: code.method_index,
            caller: caller.clone(),
            kind: "method",
            target_index: invoke.method_index,
            target: invoke.target.clone(),
            status: if invoke.target.is_some() {
                "known"
            } else {
                "unknown"
            },
            code_unit_offset: invoke.code_unit_offset,
            source_offset: source_offset(invoke.code_unit_offset),
        });
    }
    for class in &code.classes {
        references.push(DexReferenceEdge {
            dex_entry: dex_entry.to_owned(),
            caller_method_index: code.method_index,
            caller: caller.clone(),
            kind: "class",
            target_index: class.type_index,
            target: class.target.clone(),
            status: if class.target.is_some() {
                "known"
            } else {
                "unknown"
            },
            code_unit_offset: class.code_unit_offset,
            source_offset: source_offset(class.code_unit_offset),
        });
    }
    for field in &code.fields {
        references.push(DexReferenceEdge {
            dex_entry: dex_entry.to_owned(),
            caller_method_index: code.method_index,
            caller: caller.clone(),
            kind: "field",
            target_index: field.field_index,
            target: field.target.clone(),
            status: if field.target.is_some() {
                "known"
            } else {
                "unknown"
            },
            code_unit_offset: field.code_unit_offset,
            source_offset: source_offset(field.code_unit_offset),
        });
    }
    references
}

fn decode_try_blocks(
    bytes: &[u8],
    insns_end: usize,
    insns_size: u32,
    tries_size: u16,
    types: &[String],
) -> (Vec<DexTryBlock>, Vec<String>) {
    let mut issues = Vec::new();
    let padding = if insns_size % 2 == 1 { 2 } else { 0 };
    let Some(tries_start) = insns_end.checked_add(padding) else {
        return (
            Vec::new(),
            vec!["code_item try-array offset overflows".into()],
        );
    };
    let Some(tries_bytes) = (tries_size as usize).checked_mul(8) else {
        return (
            Vec::new(),
            vec!["code_item try-array size overflows".into()],
        );
    };
    let Some(handlers_start) = tries_start.checked_add(tries_bytes) else {
        return (
            Vec::new(),
            vec!["code_item handler offset overflows".into()],
        );
    };
    if handlers_start > bytes.len() {
        return (Vec::new(), vec!["code_item try-array is truncated".into()]);
    }

    let mut handler_offsets = Vec::with_capacity(tries_size as usize);
    let mut tries = Vec::with_capacity(tries_size as usize);
    for index in 0..tries_size as usize {
        let source = tries_start + index * 8;
        let start = match read_u32_at(bytes, source) {
            Ok(value) => value,
            Err(_) => {
                issues.push("code_item try entry is truncated".into());
                break;
            }
        };
        let count = match read_u16_at(bytes, source + 4) {
            Ok(value) => value,
            Err(_) => {
                issues.push("code_item try entry count is truncated".into());
                break;
            }
        };
        let handler_offset = match read_u16_at(bytes, source + 6) {
            Ok(value) => value,
            Err(_) => {
                issues.push("code_item try handler offset is truncated".into());
                break;
            }
        };
        handler_offsets.push(handler_offset);
        let mut try_block = DexTryBlock {
            source_offset: source as u32,
            start_code_unit: start,
            insn_count: count,
            handler_offset,
            handlers: Vec::new(),
            issues: Vec::new(),
        };
        if start
            .checked_add(count as u32)
            .is_none_or(|end| end > insns_size)
        {
            try_block
                .issues
                .push("try range extends beyond code_item instructions".into());
        }
        tries.push(try_block);
    }

    for (index, handler_offset) in handler_offsets.into_iter().enumerate() {
        let Some(handler_start) = handlers_start.checked_add(handler_offset as usize) else {
            tries[index]
                .issues
                .push("catch-handler offset overflows".into());
            continue;
        };
        let mut cursor = handler_start;
        let Ok(encoded_size) = read_sleb(bytes, &mut cursor) else {
            tries[index]
                .issues
                .push("catch-handler size is malformed".into());
            continue;
        };
        let typed_count = encoded_size.unsigned_abs().min(100_000) as usize;
        if encoded_size.unsigned_abs() > 100_000 {
            tries[index]
                .issues
                .push("catch-handler count exceeds the maximum".into());
            continue;
        }
        for _ in 0..typed_count {
            let type_index = match read_uleb(bytes, &mut cursor) {
                Ok(value) => value,
                Err(_) => {
                    tries[index]
                        .issues
                        .push("catch-handler type index is malformed".into());
                    break;
                }
            };
            let address = match read_uleb(bytes, &mut cursor) {
                Ok(value) => value,
                Err(_) => {
                    tries[index]
                        .issues
                        .push("catch-handler address is malformed".into());
                    break;
                }
            };
            tries[index].handlers.push(DexExceptionHandler {
                source_offset: cursor.saturating_sub(1) as u32,
                type_index: Some(type_index),
                type_descriptor: types.get(type_index as usize).cloned(),
                address,
            });
        }
        if encoded_size <= 0 {
            match read_uleb(bytes, &mut cursor) {
                Ok(address) => tries[index].handlers.push(DexExceptionHandler {
                    source_offset: cursor.saturating_sub(1) as u32,
                    type_index: None,
                    type_descriptor: None,
                    address,
                }),
                Err(_) => tries[index]
                    .issues
                    .push("catch-all handler address is malformed".into()),
            }
        }
    }
    (tries, issues)
}

fn decode_debug_info(
    bytes: &[u8],
    offset: u32,
    string_values: &[String],
) -> (DexDebugInfo, Vec<String>) {
    let mut cursor = offset as usize;
    let mut issues: Vec<String> = Vec::new();
    let line_start = match read_sleb(bytes, &mut cursor) {
        Ok(value) => value,
        Err(message) => {
            issues.push(message.to_string());
            return (DexDebugInfo::default(), issues);
        }
    };
    let parameter_count = match read_uleb(bytes, &mut cursor) {
        Ok(value) => value as usize,
        Err(message) => {
            issues.push(message.to_string());
            return (
                DexDebugInfo {
                    line_start,
                    ..Default::default()
                },
                issues,
            );
        }
    };
    if parameter_count > 100_000 {
        issues.push("DEX debug parameter count exceeds the maximum".into());
        return (
            DexDebugInfo {
                line_start,
                ..Default::default()
            },
            issues,
        );
    }
    let mut parameters = Vec::with_capacity(parameter_count);
    for _ in 0..parameter_count {
        match read_uleb(bytes, &mut cursor) {
            Ok(index) => parameters.push(
                index
                    .checked_sub(1)
                    .and_then(|i| string_values.get(i as usize).cloned()),
            ),
            Err(message) => {
                issues.push(message.to_string());
                break;
            }
        }
    }
    let mut debug = DexDebugInfo {
        line_start,
        parameters,
        ..Default::default()
    };
    let mut address = 0u32;
    let mut line = line_start;
    let mut active_locals = BTreeSet::new();
    for _ in 0..100_000 {
        let opcode = match bytes.get(cursor).copied() {
            Some(opcode) => {
                cursor += 1;
                opcode
            }
            None => {
                issues.push("DEX debug info stream is truncated".into());
                break;
            }
        };
        match opcode {
            0x00 => break,
            0x01 => match read_uleb(bytes, &mut cursor) {
                Ok(delta) => address = address.saturating_add(delta),
                Err(message) => {
                    issues.push(message.to_string());
                    break;
                }
            },
            0x02 => match read_sleb(bytes, &mut cursor) {
                Ok(delta) => line = line.saturating_add(delta),
                Err(message) => {
                    issues.push(message.to_string());
                    break;
                }
            },
            0x03 | 0x04 => {
                let register = match read_uleb(bytes, &mut cursor) {
                    Ok(v) => v,
                    Err(m) => {
                        issues.push(m.to_string());
                        break;
                    }
                };
                let name = match read_uleb(bytes, &mut cursor) {
                    Ok(v) => v
                        .checked_sub(1)
                        .and_then(|i| string_values.get(i as usize).cloned()),
                    Err(m) => {
                        issues.push(m.to_string());
                        break;
                    }
                };
                let local_type = match read_uleb(bytes, &mut cursor) {
                    Ok(v) => v
                        .checked_sub(1)
                        .and_then(|i| string_values.get(i as usize).cloned()),
                    Err(m) => {
                        issues.push(m.to_string());
                        break;
                    }
                };
                let signature = if opcode == 0x04 {
                    match read_uleb(bytes, &mut cursor) {
                        Ok(v) => v
                            .checked_sub(1)
                            .and_then(|i| string_values.get(i as usize).cloned()),
                        Err(m) => {
                            issues.push(m.to_string());
                            break;
                        }
                    }
                } else {
                    None
                };
                let local_index = debug.locals.len();
                debug.locals.push(DexDebugLocal {
                    register,
                    name,
                    local_type,
                    signature,
                    start_code_unit: address,
                    end_code_unit: None,
                });
                active_locals.insert((register, local_index));
            }
            0x05 => close_debug_local(
                &mut debug.locals,
                &mut active_locals,
                bytes,
                &mut cursor,
                address,
                &mut issues,
            ),
            0x06 => {
                let register = match read_uleb(bytes, &mut cursor) {
                    Ok(v) => v,
                    Err(m) => {
                        issues.push(m.to_string());
                        break;
                    }
                };
                if let Some(index) = debug
                    .locals
                    .iter()
                    .rposition(|local| local.register == register && local.end_code_unit.is_some())
                {
                    debug.locals[index].end_code_unit = None;
                    debug.locals[index].start_code_unit = address;
                    active_locals.insert((register, index));
                }
            }
            0x07 | 0x08 => {}
            0x09 => {
                if let Err(message) = read_uleb(bytes, &mut cursor) {
                    issues.push(message.to_string());
                    break;
                }
            }
            0x0a..=0xff => {
                let adjusted = opcode as u32 - 0x0a;
                address = address.saturating_add(adjusted / 15);
                line = line.saturating_add(-4 + (adjusted % 15) as i32);
                debug.lines.push(DexDebugLine {
                    code_unit_offset: address,
                    line,
                });
            }
        }
    }
    debug
        .locals
        .iter_mut()
        .filter(|local| local.end_code_unit.is_none())
        .for_each(|local| local.end_code_unit = Some(address));
    (debug, issues)
}

fn parse_annotation_directory(
    bytes: &[u8],
    offset: usize,
    types: &[String],
    strings: &[String],
    fields: &[(String, DexField)],
    methods: &[DexMethod],
) -> Vec<DexAnnotationAssociation> {
    let mut output = Vec::new();
    let Ok(class_annotations) = read_u32_at(bytes, offset) else {
        return output;
    };
    let Ok(field_count) = read_u32_at(bytes, offset + 4) else {
        return output;
    };
    let Ok(method_count) = read_u32_at(bytes, offset + 8) else {
        return output;
    };
    let Ok(parameter_count) = read_u32_at(bytes, offset + 12) else {
        return output;
    };
    if field_count > 100_000 || method_count > 100_000 || parameter_count > 100_000 {
        return output;
    }
    if class_annotations != 0 {
        output.extend(parse_annotation_set(
            bytes,
            class_annotations as usize,
            "class".into(),
            types,
            strings,
        ));
    }
    let mut cursor = offset + 16;
    for _ in 0..field_count {
        let Ok(index) = read_u32_at(bytes, cursor) else {
            break;
        };
        let Ok(set) = read_u32_at(bytes, cursor + 4) else {
            break;
        };
        let owner = fields
            .get(index as usize)
            .map(|(class, field)| format!("{class}->{}", field.name))
            .unwrap_or_else(|| format!("field@{index}"));
        output.extend(parse_annotation_set(
            bytes,
            set as usize,
            owner,
            types,
            strings,
        ));
        cursor = cursor.saturating_add(8);
    }
    for _ in 0..method_count {
        let Ok(index) = read_u32_at(bytes, cursor) else {
            break;
        };
        let Ok(set) = read_u32_at(bytes, cursor + 4) else {
            break;
        };
        let owner = methods
            .get(index as usize)
            .map(|method| {
                format!(
                    "{}->{}{}",
                    method.class_descriptor, method.name, method.descriptor
                )
            })
            .unwrap_or_else(|| format!("method@{index}"));
        output.extend(parse_annotation_set(
            bytes,
            set as usize,
            owner,
            types,
            strings,
        ));
        cursor = cursor.saturating_add(8);
    }
    for _ in 0..parameter_count {
        let Ok(index) = read_u32_at(bytes, cursor) else {
            break;
        };
        let Ok(set_ref) = read_u32_at(bytes, cursor + 4) else {
            break;
        };
        let owner = methods
            .get(index as usize)
            .map(|method| {
                format!(
                    "{}->{}{}:parameters",
                    method.class_descriptor, method.name, method.descriptor
                )
            })
            .unwrap_or_else(|| format!("parameter@{index}"));
        output.extend(parse_annotation_set(
            bytes,
            set_ref as usize,
            owner,
            types,
            strings,
        ));
        cursor = cursor.saturating_add(8);
    }
    output
}

fn parse_static_values(
    bytes: &[u8],
    offset: usize,
    fields: &[u32],
    strings: &[String],
    types: &[String],
) -> Vec<DexStaticFieldValue> {
    if offset == 0 || fields.is_empty() {
        return Vec::new();
    }
    let mut cursor = offset;
    let count = match read_uleb(bytes, &mut cursor) {
        Ok(count) => count as usize,
        Err(_) => return Vec::new(),
    };
    if count > 100_000 {
        return Vec::new();
    }
    let mut values = Vec::new();
    for position in 0..count.min(fields.len()) {
        let source_offset = cursor as u32;
        match decode_annotation_value(bytes, &mut cursor, strings, types, 0) {
            Ok(value) => values.push(DexStaticFieldValue {
                field_index: fields[position],
                source_offset,
                value,
                issues: Vec::new(),
            }),
            Err(issue) => values.push(DexStaticFieldValue {
                field_index: fields[position],
                source_offset,
                value: DexEncodedValue::Unsupported {
                    value_type: 0xff,
                    raw: Vec::new(),
                },
                issues: vec![issue],
            }),
        }
    }
    values
}

fn parse_dex_link_sections(
    bytes: &[u8],
    map_offset: usize,
    strings: &[String],
    types: &[String],
    fields: &[(String, DexField)],
    methods: &[DexMethod],
) -> (Vec<DexCallSite>, Vec<DexMethodHandle>) {
    let mut call_sites = Vec::new();
    let mut method_handles = Vec::new();
    let Ok(map_count) = read_u32_at(bytes, map_offset) else {
        return (call_sites, method_handles);
    };
    if map_count > 100_000 {
        return (call_sites, method_handles);
    }
    for index in 0..map_count as usize {
        let item = map_offset.saturating_add(4 + index * 12);
        let Ok(kind) = read_u16_at(bytes, item) else {
            break;
        };
        let Ok(size) = read_u32_at(bytes, item + 4) else {
            break;
        };
        let Ok(section_offset) = read_u32_at(bytes, item + 8) else {
            break;
        };
        if size > 100_000 {
            continue;
        }
        match kind {
            0x0007 => {
                for call_index in 0..size as usize {
                    let source = section_offset as usize + call_index * 4;
                    let Ok(encoded_offset) = read_u32_at(bytes, source) else {
                        break;
                    };
                    let mut cursor = encoded_offset as usize;
                    let count = match read_uleb(bytes, &mut cursor) {
                        Ok(value) => value as usize,
                        Err(_) => {
                            call_sites.push(DexCallSite {
                                index: call_index as u32,
                                source_offset: encoded_offset,
                                values: Vec::new(),
                                issues: vec!["call-site encoded array count is malformed".into()],
                            });
                            continue;
                        }
                    };
                    if count > 100_000 {
                        call_sites.push(DexCallSite {
                            index: call_index as u32,
                            source_offset: encoded_offset,
                            values: Vec::new(),
                            issues: vec!["call-site encoded array exceeds the maximum".into()],
                        });
                        continue;
                    }
                    let mut values = Vec::with_capacity(count);
                    let mut issues = Vec::new();
                    for _ in 0..count {
                        match decode_annotation_value(bytes, &mut cursor, strings, types, 0) {
                            Ok(value) => values.push(value),
                            Err(issue) => {
                                issues.push(issue);
                                break;
                            }
                        }
                    }
                    call_sites.push(DexCallSite {
                        index: call_index as u32,
                        source_offset: encoded_offset,
                        values,
                        issues,
                    });
                }
            }
            0x0008 => {
                for handle_index in 0..size as usize {
                    let source = section_offset as usize + handle_index * 8;
                    let Ok(kind_value) = read_u16_at(bytes, source) else {
                        break;
                    };
                    let Ok(member_index) = read_u16_at(bytes, source + 4) else {
                        break;
                    };
                    let kind = match kind_value {
                        0 => "static_put",
                        1 => "static_get",
                        2 => "instance_put",
                        3 => "instance_get",
                        4 => "invoke_static",
                        5 => "invoke_instance",
                        6 => "invoke_constructor",
                        7 => "invoke_direct",
                        8 => "invoke_interface",
                        _ => "unknown",
                    };
                    let target = if kind_value <= 3 {
                        fields
                            .get(member_index as usize)
                            .map(|(class, field)| format!("{class}->{}", field.name))
                    } else {
                        methods.get(member_index as usize).map(|method| {
                            format!(
                                "{}->{}{}",
                                method.class_descriptor, method.name, method.descriptor
                            )
                        })
                    };
                    let issues = if kind_value > 8 {
                        vec!["unsupported method-handle kind".into()]
                    } else {
                        Vec::new()
                    };
                    method_handles.push(DexMethodHandle {
                        index: handle_index as u32,
                        source_offset: source as u32,
                        kind: kind.into(),
                        member_index: member_index as u32,
                        target,
                        issues,
                    });
                }
            }
            _ => {}
        }
    }
    (call_sites, method_handles)
}

fn parse_annotation_set(
    bytes: &[u8],
    offset: usize,
    owner: String,
    types: &[String],
    strings: &[String],
) -> Vec<DexAnnotationAssociation> {
    let Ok(count) = read_u32_at(bytes, offset) else {
        return Vec::new();
    };
    if count > 100_000 {
        return Vec::new();
    }
    let mut output = Vec::new();
    for index in 0..count as usize {
        let Ok(item) = read_u32_at(bytes, offset + 4 + index * 4) else {
            break;
        };
        let item = item as usize;
        let visibility = match bytes.get(item).copied() {
            Some(0) => "build",
            Some(1) => "runtime",
            Some(2) => "system",
            Some(_) => "unknown",
            None => {
                output.push(DexAnnotationAssociation {
                    owner: owner.clone(),
                    visibility: "unknown".into(),
                    type_descriptor: None,
                    elements: Vec::new(),
                    source_offset: item as u32,
                    issues: vec!["annotation visibility is truncated".into()],
                });
                continue;
            }
        };
        let mut cursor = item + 1;
        let type_index = match read_uleb(bytes, &mut cursor) {
            Ok(value) => value as usize,
            Err(_) => {
                output.push(DexAnnotationAssociation {
                    owner: owner.clone(),
                    visibility: visibility.into(),
                    type_descriptor: None,
                    elements: Vec::new(),
                    source_offset: item as u32,
                    issues: vec!["annotation type index is malformed".into()],
                });
                continue;
            }
        };
        let element_count = match read_uleb(bytes, &mut cursor) {
            Ok(value) => value as usize,
            Err(_) => {
                output.push(DexAnnotationAssociation {
                    owner: owner.clone(),
                    visibility: visibility.into(),
                    type_descriptor: types.get(type_index).cloned(),
                    elements: Vec::new(),
                    source_offset: item as u32,
                    issues: vec!["annotation element count is malformed".into()],
                });
                continue;
            }
        };
        if element_count > 100_000 {
            continue;
        }
        let mut elements = Vec::with_capacity(element_count);
        let mut issues = Vec::new();
        for _ in 0..element_count {
            let element_source_offset = cursor as u32;
            let name = match read_uleb(bytes, &mut cursor) {
                Ok(index) => strings.get(index as usize).cloned(),
                Err(_) => {
                    issues.push("annotation element name is malformed".into());
                    break;
                }
            };
            match decode_annotation_value(bytes, &mut cursor, strings, types, 0) {
                Ok(value) => elements.push(DexAnnotationElement {
                    name,
                    source_offset: element_source_offset,
                    value,
                }),
                Err(issue) => {
                    issues.push(issue);
                    break;
                }
            }
        }
        output.push(DexAnnotationAssociation {
            owner: owner.clone(),
            visibility: visibility.into(),
            type_descriptor: types.get(type_index).cloned(),
            elements,
            source_offset: item as u32,
            issues,
        });
    }
    output
}

fn decode_annotation_value(
    bytes: &[u8],
    cursor: &mut usize,
    strings: &[String],
    types: &[String],
    depth: usize,
) -> Result<DexEncodedValue, String> {
    if depth > 16 {
        return Err("annotation value nesting exceeds the maximum".into());
    }
    let value_source_offset = *cursor as u32;
    let header = *bytes
        .get(*cursor)
        .ok_or("annotation value header is truncated")?;
    *cursor += 1;
    let value_type = header & 0x1f;
    let width = ((header >> 5) + 1) as usize;
    let integer = |bytes: &[u8], cursor: &mut usize, width: usize| -> Result<i64, String> {
        if width > 8 || cursor.checked_add(width).is_none() || *cursor + width > bytes.len() {
            return Err("annotation value payload is truncated".into());
        }
        let mut raw = [0u8; 8];
        raw[..width].copy_from_slice(&bytes[*cursor..*cursor + width]);
        *cursor += width;
        Ok(i64::from_le_bytes(raw))
    };
    match value_type {
        0x00..=0x0e => Ok(DexEncodedValue::Integer(integer(bytes, cursor, width)?)),
        0x17 => Ok(DexEncodedValue::String(
            integer(bytes, cursor, width)?
                .try_into()
                .ok()
                .and_then(|index: usize| strings.get(index).cloned()),
        )),
        0x18 => Ok(DexEncodedValue::Type(
            integer(bytes, cursor, width)?
                .try_into()
                .ok()
                .and_then(|index: usize| types.get(index).cloned()),
        )),
        0x1b => {
            let index = integer(bytes, cursor, width)?;
            let index = u32::try_from(index)
                .map_err(|_| "annotation enum index is out of range".to_string())?;
            Ok(DexEncodedValue::Enum {
                index,
                name: strings.get(index as usize).cloned(),
                source_offset: value_source_offset,
            })
        }
        0x1e => Ok(DexEncodedValue::Null),
        0x1f => Ok(DexEncodedValue::Boolean((header >> 5) != 0)),
        0x1c => {
            let count = read_uleb(bytes, cursor)
                .map_err(|_| "annotation array count is malformed".to_string())?
                as usize;
            if count > 100_000 {
                return Err("annotation array count exceeds the maximum".into());
            }
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(decode_annotation_value(
                    bytes,
                    cursor,
                    strings,
                    types,
                    depth + 1,
                )?);
            }
            Ok(DexEncodedValue::Array(values))
        }
        0x1d => {
            let type_index = read_uleb(bytes, cursor)
                .map_err(|_| "nested annotation type is malformed".to_string())?
                as usize;
            let count = read_uleb(bytes, cursor)
                .map_err(|_| "nested annotation count is malformed".to_string())?
                as usize;
            if count > 100_000 {
                return Err("nested annotation count exceeds the maximum".into());
            }
            let mut elements = Vec::with_capacity(count);
            for _ in 0..count {
                let element_source_offset = *cursor as u32;
                let name = read_uleb(bytes, cursor)
                    .ok()
                    .and_then(|index| strings.get(index as usize).cloned());
                let value = decode_annotation_value(bytes, cursor, strings, types, depth + 1)?;
                elements.push(DexAnnotationElement {
                    name,
                    source_offset: element_source_offset,
                    value,
                });
            }
            Ok(DexEncodedValue::Annotation {
                type_descriptor: types.get(type_index).cloned(),
                elements,
            })
        }
        _ => Ok(DexEncodedValue::Unsupported {
            value_type,
            raw: integer(bytes, cursor, width)?.to_le_bytes()[..width.min(8)].to_vec(),
        }),
    }
}

fn close_debug_local(
    locals: &mut [DexDebugLocal],
    active: &mut BTreeSet<(u32, usize)>,
    bytes: &[u8],
    cursor: &mut usize,
    address: u32,
    issues: &mut Vec<String>,
) {
    let register = match read_uleb(bytes, cursor) {
        Ok(value) => value,
        Err(message) => {
            issues.push(message.to_string());
            return;
        }
    };
    if let Some((_, index)) = active
        .iter()
        .find(|(local_register, _)| *local_register == register)
        .copied()
    {
        if let Some(local) = locals.get_mut(index) {
            local.end_code_unit = Some(address);
        }
        active.remove(&(register, index));
    }
}
fn proto_descriptor(bytes: &[u8], types: &[String], index: usize) -> Result<String, Error> {
    let count = read_u32_at(bytes, 0x48)? as usize;
    let base = read_u32_at(bytes, 0x4c)? as usize;
    if index >= count {
        return Err(Error::Malformed("DEX prototype index is invalid"));
    }
    let offset = read_u32_at(bytes, base + index * 12)? as usize;
    let return_type = read_u32_at(bytes, offset + 4)? as usize;
    let params_offset = read_u32_at(bytes, offset + 8)? as usize;
    let mut descriptor = String::from("(");
    if params_offset != 0 {
        let parameter_count = read_u32_at(bytes, params_offset)? as usize;
        if parameter_count > 100_000 {
            return Err(Error::Resource(
                "DEX prototype parameter count exceeds the maximum",
            ));
        }
        for i in 0..parameter_count {
            let type_index = read_u16_at(bytes, params_offset + 4 + i * 2)? as usize;
            descriptor.push_str(types.get(type_index).map(String::as_str).unwrap_or("?"));
        }
    }
    descriptor.push(')');
    descriptor.push_str(types.get(return_type).map(String::as_str).unwrap_or("?"));
    Ok(descriptor)
}
fn read_uleb(bytes: &[u8], cursor: &mut usize) -> Result<u32, Error> {
    let mut value = 0;
    for shift in (0..35).step_by(7) {
        let byte = *bytes
            .get(*cursor)
            .ok_or(Error::Malformed("DEX ULEB128 is truncated"))?;
        *cursor += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Error::Malformed("DEX ULEB128 is too long"))
}

fn read_sleb(bytes: &[u8], cursor: &mut usize) -> Result<i32, &'static str> {
    let mut value = 0i32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or("DEX debug SLEB128 is truncated")?;
        *cursor += 1;
        value |= ((byte & 0x7f) as i32) << shift;
        if byte & 0x80 == 0 {
            if shift < 32 && byte & 0x40 != 0 {
                value |= !0i32 << (shift + 7);
            }
            return Ok(value);
        }
    }
    Err("DEX debug SLEB128 is too long")
}
fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(Error::Malformed("DEX value is truncated"))?
            .try_into()
            .unwrap(),
    ))
}
fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    read_u16_at(bytes, offset)
}
fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Malformed("DEX value is truncated"))?
            .try_into()
            .unwrap(),
    ))
}

struct Manifest {
    package_name: Option<String>,
    version_name: Option<String>,
    version_code: Option<String>,
    min_sdk: Option<String>,
    target_sdk: Option<String>,
    max_sdk: Option<String>,
    min_sdk_value: Option<u32>,
    target_sdk_value: Option<u32>,
    max_sdk_value: Option<u32>,
    sdk_source_offset: Option<u32>,
    application_label: Option<String>,
    application_name: Option<String>,
    application_icon: Option<String>,
    application_round_icon: Option<String>,
    allow_backup: Option<bool>,
    extract_native_libs: Option<bool>,
    uses_cleartext_traffic: Option<bool>,
    debuggable: Option<bool>,
    permissions: Vec<String>,
    permission_details: Vec<PermissionDeclaration>,
    text: String,
    binary: bool,
    components: Vec<Component>,
    features: Vec<UsesFeature>,
    supports_screens: SupportsScreens,
    queries: Option<QueryVisibility>,
    uses_libraries: Vec<LibraryDeclaration>,
    uses_native_libraries: Vec<LibraryDeclaration>,
    uses_configuration: Option<UsesConfiguration>,
}

fn resolve_manifest_resources(mut manifest: Manifest, values: Option<&ResourceTable>) -> Manifest {
    let resolve = |value: Option<String>| {
        value.map(|value| {
            values
                .and_then(|table| table.unique.get(&value))
                .cloned()
                .unwrap_or(value)
        })
    };
    manifest.version_name = resolve(manifest.version_name);
    manifest.version_code = resolve(manifest.version_code);
    manifest.application_label = resolve(manifest.application_label);
    manifest.application_name = resolve(manifest.application_name);
    manifest.application_icon = resolve(manifest.application_icon);
    manifest.application_round_icon = resolve(manifest.application_round_icon);
    manifest.permissions = manifest
        .permissions
        .into_iter()
        .map(|value| {
            values
                .and_then(|table| table.unique.get(&value))
                .cloned()
                .unwrap_or(value)
        })
        .collect();
    manifest
}

#[derive(Debug, Default)]
struct ResourceTable {
    unique: std::collections::BTreeMap<String, String>,
    unique_entries: std::collections::BTreeMap<String, ResourceEntry>,
    variants: Vec<ResourceVariant>,
    string_pool: ResourceStringPool,
    packages: Vec<ResourcePackage>,
    pools: Vec<ResourcePool>,
    entries: Vec<ResourceEntry>,
}

struct ResourcePoolMapping<'a> {
    package_id: u32,
    package_name: Option<&'a str>,
    package_name_source_offset: u32,
    type_pool: Option<&'a StringPool>,
    type_pool_source_offset: Option<u32>,
    type_pool_issue: Option<&'a str>,
    key_pool: Option<&'a StringPool>,
    key_pool_source_offset: Option<u32>,
    key_pool_issue: Option<&'a str>,
}

#[derive(Clone)]
struct ResourceNameFacts {
    package_id: u32,
    package_name: Option<String>,
    package_name_source_offset: Option<u32>,
    type_name: Option<String>,
    type_name_index: Option<u32>,
    type_pool_source_offset: Option<u32>,
    key_name: Option<String>,
    qualified_name: Option<String>,
    key_name_index: Option<u32>,
    key_pool_source_offset: Option<u32>,
    mapping_issue: Option<String>,
}

fn parse_resource_table(bytes: &[u8]) -> Result<ResourceTable, Error> {
    if bytes.len() < 8 || read_le_u16(bytes, 0)? != 0x0002 {
        return Err(Error::Malformed("resources.arsc table header is invalid"));
    }
    let table_size = read_u32_at(bytes, 4)? as usize;
    if table_size > bytes.len() {
        return Err(Error::Malformed("resources.arsc table is truncated"));
    }
    let global_pool = StringPool::read(bytes, 8)?;
    let mut values = ResourceTable::default();
    values.string_pool = ResourceStringPool {
        count: global_pool.values.len(),
        strings: global_pool.values.iter().take(10_000).cloned().collect(),
        encoding: if global_pool.utf8 { "utf-8" } else { "utf-16" }.into(),
        entry_source_ranges: global_pool
            .entry_source_ranges
            .iter()
            .take(10_000)
            .map(|(start, end)| (*start as u32, *end as u32))
            .collect(),
        invalid_utf16_indices: global_pool
            .invalid_utf16
            .iter()
            .take(10_000)
            .map(|index| *index as u32)
            .collect(),
        invalid_utf16_source_offsets: global_pool
            .invalid_utf16_source_offsets
            .iter()
            .take(10_000)
            .map(|offset| *offset as u32)
            .collect(),
        source_offset: 8,
    };
    let mut offset = 8 + global_pool.chunk_size;
    while offset + 8 <= table_size {
        let kind = read_le_u16(bytes, offset)?;
        let header_size = read_le_u16(bytes, offset + 2)? as usize;
        let size = read_u32_at(bytes, offset + 4)? as usize;
        if header_size < 8 || size < header_size || offset + size > table_size {
            return Err(Error::Malformed("resources.arsc chunk is truncated"));
        }
        if kind == 0x0200 {
            let package_id = read_u32_at(bytes, offset + 8)? & 0xff;
            let (name, name_issue) = resource_package_name_facts(bytes, offset);
            values.packages.push(ResourcePackage {
                package_id,
                name,
                name_issue,
                source_offset: offset as u32,
                library_mappings: Vec::new(),
                staged_aliases: Vec::new(),
            });
            parse_resource_package(bytes, offset, size, &global_pool, &mut values)?;
        }
        offset += size;
    }
    Ok(values)
}

fn parse_resource_package(
    bytes: &[u8],
    package_offset: usize,
    package_size: usize,
    global_pool: &StringPool,
    values: &mut ResourceTable,
) -> Result<(), Error> {
    if package_size < 288 {
        return Err(Error::Malformed(
            "resources.arsc package header is truncated",
        ));
    }
    let package_id = read_u32_at(bytes, package_offset + 8)? & 0xff;
    let mut offset = package_offset + 288;
    let package_end = package_offset + package_size;
    let mut package_pool_index = 0usize;
    let package_name = resource_package_name(bytes, package_offset);
    let mut type_pool = None;
    let mut type_pool_source_offset = None;
    let mut type_pool_issue = None;
    let mut key_pool = None;
    let mut key_pool_source_offset = None;
    let mut key_pool_issue = None;
    while offset + 8 <= package_end {
        let kind = read_le_u16(bytes, offset)?;
        let header_size = read_le_u16(bytes, offset + 2)? as usize;
        let size = read_u32_at(bytes, offset + 4)? as usize;
        if header_size < 8 || size < header_size || offset + size > package_end {
            return Err(Error::Malformed(
                "resources.arsc package chunk is truncated",
            ));
        }
        if kind == 0x0001 {
            let pool_kind = if package_pool_index == 0 {
                "type"
            } else {
                "key"
            };
            match StringPool::read(bytes, offset) {
                Ok(pool) => {
                    values.pools.push(ResourcePool {
                        package_id,
                        package_name: package_name.clone(),
                        kind: pool_kind.into(),
                        count: pool.values.len(),
                        strings: pool.values.iter().take(10_000).cloned().collect(),
                        encoding: if pool.utf8 { "utf-8" } else { "utf-16" }.into(),
                        entry_source_ranges: pool
                            .entry_source_ranges
                            .iter()
                            .take(10_000)
                            .map(|(start, end)| (*start as u32, *end as u32))
                            .collect(),
                        invalid_utf16_indices: pool
                            .invalid_utf16
                            .iter()
                            .take(10_000)
                            .map(|index| *index as u32)
                            .collect(),
                        invalid_utf16_source_offsets: pool
                            .invalid_utf16_source_offsets
                            .iter()
                            .take(10_000)
                            .map(|offset| *offset as u32)
                            .collect(),
                        source_offset: offset as u32,
                        issue: None,
                    });
                    if package_pool_index == 0 {
                        type_pool = Some(pool);
                        type_pool_source_offset = Some(offset as u32);
                    } else if package_pool_index == 1 {
                        key_pool = Some(pool);
                        key_pool_source_offset = Some(offset as u32);
                    }
                }
                Err(_) => {
                    let issue = "resource package string pool is malformed";
                    values.pools.push(ResourcePool {
                        package_id,
                        package_name: package_name.clone(),
                        kind: pool_kind.into(),
                        source_offset: offset as u32,
                        issue: Some(issue.into()),
                        ..ResourcePool::default()
                    });
                    if package_pool_index == 0 {
                        type_pool_issue = Some(issue);
                    } else if package_pool_index == 1 {
                        key_pool_issue = Some(issue);
                    }
                }
            }
            package_pool_index = package_pool_index.saturating_add(1);
        } else if kind == 0x0201 {
            let mapping = ResourcePoolMapping {
                package_id,
                package_name: package_name.as_deref(),
                package_name_source_offset: (package_offset + 12) as u32,
                type_pool: type_pool.as_ref(),
                type_pool_source_offset,
                type_pool_issue,
                key_pool: key_pool.as_ref(),
                key_pool_source_offset,
                key_pool_issue,
            };
            parse_resource_type_chunk(bytes, offset, size, &mapping, global_pool, values)?;
        } else if kind == 0x0203 {
            let mappings = parse_resource_library_chunk(bytes, offset, size);
            if let Some(package) = values
                .packages
                .iter_mut()
                .find(|package| package.package_id == package_id)
            {
                package.library_mappings.extend(mappings);
            }
        } else if kind == 0x0206 {
            let aliases = parse_resource_staged_alias_chunk(bytes, offset, size);
            if let Some(package) = values
                .packages
                .iter_mut()
                .find(|package| package.package_id == package_id)
            {
                package.staged_aliases.extend(aliases);
            }
        }
        offset += size;
    }
    Ok(())
}

fn resource_package_name(bytes: &[u8], package_offset: usize) -> Option<String> {
    resource_package_name_facts(bytes, package_offset).0
}

fn parse_resource_library_chunk(
    bytes: &[u8],
    offset: usize,
    size: usize,
) -> Vec<ResourceLibraryMapping> {
    const ENTRY_SIZE: usize = 4 + 128 * 2;
    let source_end = offset.saturating_add(size).min(bytes.len());
    let Some(count) = read_u32_at(bytes, offset + 8)
        .ok()
        .map(|value| value as usize)
    else {
        return vec![ResourceLibraryMapping {
            source_range: (offset as u32, source_end as u32),
            issue: Some("resource library mapping count is truncated".into()),
            ..ResourceLibraryMapping::default()
        }];
    };
    if count > 10_000 {
        return vec![ResourceLibraryMapping {
            source_range: (offset as u32, source_end as u32),
            issue: Some("resource library mapping count exceeds the maximum".into()),
            ..ResourceLibraryMapping::default()
        }];
    }
    let entries_start = offset.saturating_add(12);
    let mut mappings = Vec::with_capacity(count);
    for index in 0..count {
        let entry_offset = entries_start.saturating_add(index.saturating_mul(ENTRY_SIZE));
        let entry_end = entry_offset.saturating_add(ENTRY_SIZE);
        if entry_end > source_end {
            mappings.push(ResourceLibraryMapping {
                source_range: (entry_offset as u32, source_end as u32),
                issue: Some("resource library mapping is truncated".into()),
                ..ResourceLibraryMapping::default()
            });
            break;
        }
        let package_id = read_u32_at(bytes, entry_offset).ok();
        let name_bytes = &bytes[entry_offset + 4..entry_end];
        let units = name_bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        let package_name = String::from_utf16(&units)
            .ok()
            .filter(|name| !name.is_empty());
        let issue = package_name
            .is_none()
            .then_some("resource library package name is invalid or empty".into());
        mappings.push(ResourceLibraryMapping {
            package_id,
            package_name,
            source_range: (entry_offset as u32, entry_end as u32),
            issue,
        });
    }
    mappings
}

fn parse_resource_staged_alias_chunk(
    bytes: &[u8],
    offset: usize,
    size: usize,
) -> Vec<ResourceStagedAlias> {
    const ENTRY_SIZE: usize = 8;
    const MAX_ENTRIES: usize = 10_000;

    let source_end = offset.saturating_add(size).min(bytes.len());
    if source_end < offset.saturating_add(12) {
        return vec![ResourceStagedAlias {
            source_range: (offset as u32, source_end as u32),
            issue: Some("resource staged alias count is truncated".into()),
            ..ResourceStagedAlias::default()
        }];
    }
    let Some(count) = read_u32_at(bytes, offset + 8)
        .ok()
        .map(|value| value as usize)
    else {
        return vec![ResourceStagedAlias {
            source_range: (offset as u32, source_end as u32),
            issue: Some("resource staged alias count is truncated".into()),
            ..ResourceStagedAlias::default()
        }];
    };

    if count > MAX_ENTRIES {
        return vec![ResourceStagedAlias {
            source_range: (offset as u32, source_end as u32),
            issue: Some("resource staged alias count exceeds the maximum".into()),
            ..ResourceStagedAlias::default()
        }];
    }

    let entries_start = offset.saturating_add(12);
    let mut aliases = Vec::with_capacity(count);
    for index in 0..count {
        let entry_offset = entries_start.saturating_add(index.saturating_mul(ENTRY_SIZE));
        let entry_end = entry_offset.saturating_add(ENTRY_SIZE);
        if entry_end > source_end {
            aliases.push(ResourceStagedAlias {
                source_range: (entry_offset as u32, source_end as u32),
                issue: Some("resource staged alias is truncated".into()),
                ..ResourceStagedAlias::default()
            });
            break;
        }

        let staged_id_raw = read_u32_at(bytes, entry_offset).ok();
        let final_id_raw = read_u32_at(bytes, entry_offset + 4).ok();
        let issue = if staged_id_raw.is_none() || final_id_raw.is_none() {
            Some("resource staged alias record is malformed".into())
        } else {
            None
        };
        aliases.push(ResourceStagedAlias {
            staged_id: staged_id_raw.map(format_resource_id),
            final_id: final_id_raw.map(format_resource_id),
            staged_id_raw,
            final_id_raw,
            source_range: (entry_offset as u32, entry_end as u32),
            issue,
        });
    }
    aliases
}

fn format_resource_id(resource_id: u32) -> String {
    format!("0x{resource_id:08x}")
}

fn resource_package_name_facts(
    bytes: &[u8],
    package_offset: usize,
) -> (Option<String>, Option<String>) {
    let Some(raw) = bytes.get(package_offset + 12..package_offset + 12 + 256) else {
        return (
            None,
            Some("resource package name field is truncated".into()),
        );
    };
    let mut units = Vec::new();
    for pair in raw.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if units.is_empty() {
        return (None, None);
    }
    match String::from_utf16(&units) {
        Ok(name) => (Some(name), None),
        Err(_) => (
            None,
            Some("resource package name contains invalid UTF-16".into()),
        ),
    }
}

fn resource_name_facts(
    mapping: &ResourcePoolMapping<'_>,
    type_id: u32,
    key_index: Option<u32>,
) -> ResourceNameFacts {
    let type_name_index = type_id.checked_sub(1);
    let (type_name, type_issue) = resource_pool_name(
        mapping.type_pool,
        type_name_index,
        mapping.type_pool_issue,
        "type",
    );
    let (key_name, key_issue) =
        resource_pool_name(mapping.key_pool, key_index, mapping.key_pool_issue, "key");
    let mut issues = Vec::new();
    if let Some(issue) = type_issue {
        issues.push(issue);
    }
    if let Some(issue) = key_issue {
        issues.push(issue);
    }
    let qualified_name = match (
        mapping.package_name,
        type_name.as_deref(),
        key_name.as_deref(),
    ) {
        (Some(package), Some(resource_type), Some(key)) => {
            Some(format!("{package}:{resource_type}/{key}"))
        }
        _ => None,
    };
    ResourceNameFacts {
        package_id: mapping.package_id,
        package_name: mapping.package_name.map(str::to_owned),
        package_name_source_offset: Some(mapping.package_name_source_offset),
        type_name,
        type_name_index,
        type_pool_source_offset: mapping.type_pool_source_offset,
        key_name,
        qualified_name,
        key_name_index: key_index,
        key_pool_source_offset: mapping.key_pool_source_offset,
        mapping_issue: (!issues.is_empty()).then(|| issues.join("; ")),
    }
}

fn resource_pool_name(
    pool: Option<&StringPool>,
    index: Option<u32>,
    pool_issue: Option<&str>,
    kind: &str,
) -> (Option<String>, Option<String>) {
    let Some(index) = index else {
        return (None, Some(format!("resource {kind} pool index is absent")));
    };
    let Some(pool) = pool else {
        return (
            None,
            Some(
                pool_issue
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("resource {kind} pool is unavailable")),
            ),
        );
    };
    let Some(name) = pool.get(index as usize) else {
        return (
            None,
            Some(format!("resource {kind} pool index {index} is unresolved")),
        );
    };
    let invalid = pool.invalid_utf16.contains(&(index as usize));
    let issue = invalid.then(|| format!("resource {kind} pool entry contains invalid UTF-16"));
    (Some(name.to_owned()), issue)
}

fn string_pool_entry_source_offset(pool: &StringPool, index: usize) -> Option<u32> {
    pool.entry_source_ranges
        .get(index)
        .map(|(start, _)| *start as u32)
        .or_else(|| Some(pool.source_offset.saturating_add(8)))
}

fn with_resource_name_facts(mut entry: ResourceEntry, facts: ResourceNameFacts) -> ResourceEntry {
    entry.package_id = facts.package_id;
    entry.package_name = facts.package_name;
    entry.package_name_source_offset = facts.package_name_source_offset;
    entry.type_name = facts.type_name;
    entry.type_name_index = facts.type_name_index;
    entry.type_pool_source_offset = facts.type_pool_source_offset;
    entry.key_name = facts.key_name;
    entry.qualified_name = facts.qualified_name;
    entry.key_name_index = facts.key_name_index;
    entry.key_pool_source_offset = facts.key_pool_source_offset;
    entry.mapping_issue = facts.mapping_issue;
    entry
}

fn parse_resource_type_chunk(
    bytes: &[u8],
    offset: usize,
    size: usize,
    mapping: &ResourcePoolMapping<'_>,
    global_pool: &StringPool,
    values: &mut ResourceTable,
) -> Result<(), Error> {
    if size < 28 {
        return Err(Error::Malformed("resources.arsc type chunk is truncated"));
    }
    let type_id = bytes[offset + 8] as u32;
    let type_flags = bytes[offset + 9];
    let entry_count = read_u32_at(bytes, offset + 12)? as usize;
    if entry_count > 100_000 {
        return Err(Error::Resource(
            "resources.arsc entry count exceeds the maximum",
        ));
    }
    let entries_start = read_u32_at(bytes, offset + 20)? as usize;
    let config_size = read_u32_at(bytes, offset + 24)? as usize;
    let offsets_start = offset + 28;
    let offset_kind = if type_flags & 0x01 != 0 {
        "sparse16"
    } else {
        "dense32"
    };
    if config_size < 4 || offsets_start + entry_count * 4 > offset + size {
        return Err(Error::Malformed(
            "resources.arsc entry offsets are truncated",
        ));
    }
    for index in 0..entry_count {
        let offset_record = offsets_start + index * 4;
        let (entry_index, entry_offset) = if type_flags & 0x01 != 0 {
            let sparse_index = read_le_u16(bytes, offset_record)? as usize;
            let sparse_offset = read_le_u16(bytes, offset_record + 2)? as u32;
            (sparse_index, sparse_offset.saturating_mul(4))
        } else {
            (index, read_u32_at(bytes, offset_record)?)
        };
        let offset_source_range = Some((offset_record as u32, (offset_record + 4) as u32));
        let resource_id = format!(
            "@0x{:08x}",
            (mapping.package_id << 24) | (type_id << 16) | entry_index as u32
        );
        let key_index = if entry_offset == u32::MAX {
            None
        } else {
            let entry = offset
                .checked_add(entries_start)
                .and_then(|base| base.checked_add(entry_offset as usize));
            entry.and_then(|entry| read_u32_at(bytes, entry + 4).ok())
        };
        let name_facts = resource_name_facts(mapping, type_id, key_index);
        if entry_offset == u32::MAX {
            values.entries.push(with_resource_name_facts(
                ResourceEntry {
                    resource_id: resource_id.clone(),
                    type_id,
                    entry_index: entry_index as u32,
                    source_offset: offset_record as u32,
                    offset_kind: Some(offset_kind.into()),
                    offset_source_range,
                    issue: Some("sparse resource entry".into()),
                    ..ResourceEntry::default()
                },
                name_facts,
            ));
            continue;
        }
        let entry = offset
            .checked_add(entries_start)
            .and_then(|base| base.checked_add(entry_offset as usize))
            .ok_or(Error::Malformed("resources.arsc entry offset overflows"))?;
        if entry + 8 > offset + size {
            values.entries.push(with_resource_name_facts(
                ResourceEntry {
                    resource_id: resource_id.clone(),
                    type_id,
                    entry_index: entry_index as u32,
                    source_offset: entry as u32,
                    offset_kind: Some(offset_kind.into()),
                    offset_source_range,
                    issue: Some("resource entry is truncated".into()),
                    ..ResourceEntry::default()
                },
                name_facts,
            ));
            continue;
        }
        // ResTable_entry stores its size first, followed by the flags word.
        // Reading the size as flags incorrectly classifies ordinary values as
        // complex entries whenever the header size has bit zero set.
        let flags = read_le_u16(bytes, entry + 2)?;
        let entry_size = read_le_u16(bytes, entry + 0).ok();
        if flags & 1 != 0 {
            let (parent_id, complex_values, issue) =
                parse_resource_complex_values(bytes, entry, offset + size, global_pool);
            values.entries.push(with_resource_name_facts(
                ResourceEntry {
                    resource_id,
                    type_id,
                    entry_index: entry_index as u32,
                    offset_kind: Some(offset_kind.into()),
                    offset_source_range,
                    source_offset: entry as u32,
                    parent_id,
                    complex_values,
                    issue,
                    flags: Some(flags),
                    entry_size,
                    ..ResourceEntry::default()
                },
                name_facts,
            ));
            continue;
        }
        if entry + 16 > offset + size {
            values.entries.push(with_resource_name_facts(
                ResourceEntry {
                    resource_id,
                    type_id,
                    entry_index: entry_index as u32,
                    offset_kind: Some(offset_kind.into()),
                    offset_source_range,
                    source_offset: entry as u32,
                    issue: Some("resource entry is truncated".into()),
                    flags: Some(flags),
                    entry_size,
                    ..ResourceEntry::default()
                },
                name_facts,
            ));
            continue;
        }
        let value_type = bytes[entry + 11];
        let value_size = read_le_u16(bytes, entry + 8).ok();
        let value_res0 = bytes.get(entry + 10).copied();
        if value_type != 0x03 {
            let value_data = read_u32_at(bytes, entry + 12).unwrap_or_default();
            let decoded_value = decode_resource_value(value_type, value_data);
            let display_value =
                resource_variant_display(value_type, value_data, decoded_value.as_deref());
            values.variants.push(ResourceVariant {
                resource_id: resource_id.clone(),
                package_id: name_facts.package_id,
                package_name: name_facts.package_name.clone(),
                package_name_source_offset: name_facts.package_name_source_offset,
                type_id,
                type_name: name_facts.type_name.clone(),
                type_name_index: name_facts.type_name_index,
                type_pool_source_offset: name_facts.type_pool_source_offset,
                key_name: name_facts.key_name.clone(),
                qualified_name: name_facts.qualified_name.clone(),
                key_name_index: name_facts.key_name_index,
                key_pool_source_offset: name_facts.key_pool_source_offset,
                mapping_issue: name_facts.mapping_issue.clone(),
                configuration: resource_configuration(bytes, offset + 24, config_size),
                configuration_facts: resource_configuration_facts(bytes, offset + 24, config_size),
                value: resource_variant_display(value_type, value_data, decoded_value.as_deref()),
                value_issue: resource_value_issue(value_type, value_data, decoded_value.as_deref()),
                value_string_pool_index: None,
                value_string_pool_source_offset: None,
                source_offset: entry as u32,
            });
            let resource_entry = with_resource_name_facts(
                ResourceEntry {
                    resource_id: resource_id.clone(),
                    type_id,
                    entry_index: entry_index as u32,
                    offset_kind: Some(offset_kind.into()),
                    offset_source_range,
                    source_offset: entry as u32,
                    issue: Some("resource value is not a string".into()),
                    value_type: Some(value_type),
                    value_data: Some(value_data),
                    value_size,
                    value_res0,
                    decoded_value,
                    reference_id: resource_reference(value_type, value_data),
                    flags: Some(flags),
                    entry_size,
                    ..ResourceEntry::default()
                },
                name_facts,
            );
            values.entries.push(resource_entry.clone());
            if values.unique.contains_key(&resource_id) {
                values.unique.remove(&resource_id);
                values.unique_entries.remove(&resource_id);
            } else {
                values.unique.insert(resource_id.clone(), display_value);
                values.unique_entries.insert(resource_id, resource_entry);
            }
            continue;
        }
        let string_pool_index = read_u32_at(bytes, entry + 12)?;
        let string_index = string_pool_index as usize;
        let Some(value) = global_pool.get(string_index) else {
            values.variants.push(ResourceVariant {
                resource_id: resource_id.clone(),
                package_id: name_facts.package_id,
                package_name: name_facts.package_name.clone(),
                package_name_source_offset: name_facts.package_name_source_offset,
                type_id,
                type_name: name_facts.type_name.clone(),
                type_name_index: name_facts.type_name_index,
                type_pool_source_offset: name_facts.type_pool_source_offset,
                key_name: name_facts.key_name.clone(),
                qualified_name: name_facts.qualified_name.clone(),
                key_name_index: name_facts.key_name_index,
                key_pool_source_offset: name_facts.key_pool_source_offset,
                mapping_issue: name_facts.mapping_issue.clone(),
                configuration: resource_configuration(bytes, offset + 24, config_size),
                configuration_facts: resource_configuration_facts(bytes, offset + 24, config_size),
                value: format!("<string-pool:{string_pool_index}>"),
                value_issue: Some("resource string index is unresolved".into()),
                value_string_pool_index: Some(string_pool_index),
                value_string_pool_source_offset: string_pool_entry_source_offset(
                    global_pool,
                    string_pool_index as usize,
                ),
                source_offset: entry as u32,
            });
            values.entries.push(with_resource_name_facts(
                ResourceEntry {
                    resource_id,
                    type_id,
                    entry_index: entry_index as u32,
                    offset_kind: Some(offset_kind.into()),
                    offset_source_range,
                    source_offset: entry as u32,
                    issue: Some("resource string index is unresolved".into()),
                    value_type: Some(value_type),
                    value_data: Some(string_pool_index),
                    value_size,
                    value_res0,
                    string_pool_index: Some(string_pool_index),
                    string_pool_source_offset: string_pool_entry_source_offset(
                        global_pool,
                        string_pool_index as usize,
                    ),
                    flags: Some(flags),
                    entry_size,
                    ..ResourceEntry::default()
                },
                name_facts,
            ));
            continue;
        };
        let issue = global_pool
            .invalid_utf16
            .contains(&string_index)
            .then_some("resource string contains invalid UTF-16".to_owned());
        let resource_id = (mapping.package_id << 24) | (type_id << 16) | index as u32;
        let resource_key = format!("@0x{resource_id:08x}");
        let configuration = resource_configuration(bytes, offset + 24, config_size);
        let configuration_facts = resource_configuration_facts(bytes, offset + 24, config_size);
        values.variants.push(ResourceVariant {
            resource_id: resource_key.clone(),
            package_id: name_facts.package_id,
            package_name: name_facts.package_name.clone(),
            package_name_source_offset: name_facts.package_name_source_offset,
            type_id,
            type_name: name_facts.type_name.clone(),
            type_name_index: name_facts.type_name_index,
            type_pool_source_offset: name_facts.type_pool_source_offset,
            key_name: name_facts.key_name.clone(),
            qualified_name: name_facts.qualified_name.clone(),
            key_name_index: name_facts.key_name_index,
            key_pool_source_offset: name_facts.key_pool_source_offset,
            mapping_issue: name_facts.mapping_issue.clone(),
            configuration,
            configuration_facts: configuration_facts.clone(),
            value: value.to_owned(),
            value_issue: issue.clone(),
            value_string_pool_index: Some(string_pool_index),
            value_string_pool_source_offset: string_pool_entry_source_offset(
                global_pool,
                string_pool_index as usize,
            ),
            source_offset: entry as u32,
        });
        let resource_entry = with_resource_name_facts(
            ResourceEntry {
                resource_id: resource_key.clone(),
                type_id,
                entry_index: entry_index as u32,
                offset_kind: Some(offset_kind.into()),
                offset_source_range,
                value: Some(value.to_owned()),
                source_offset: entry as u32,
                issue,
                configuration: resource_configuration_facts(bytes, offset + 24, config_size),
                value_type: Some(value_type),
                value_data: Some(read_u32_at(bytes, entry + 12).unwrap_or_default()),
                value_size,
                value_res0,
                decoded_value: Some(value.to_owned()),
                string_pool_index: Some(string_pool_index),
                string_pool_source_offset: string_pool_entry_source_offset(
                    global_pool,
                    string_pool_index as usize,
                ),
                flags: Some(flags),
                entry_size,
                ..ResourceEntry::default()
            },
            name_facts,
        );
        values.entries.push(resource_entry.clone());
        if values.unique.contains_key(&resource_key) {
            values.unique.remove(&resource_key);
            values.unique_entries.remove(&resource_key);
        } else {
            values.unique.insert(resource_key.clone(), value.to_owned());
            values.unique_entries.insert(resource_key, resource_entry);
        }
    }
    Ok(())
}

fn parse_resource_complex_values(
    bytes: &[u8],
    entry: usize,
    chunk_end: usize,
    global_pool: &StringPool,
) -> (Option<u32>, Vec<ResourceComplexValue>, Option<String>) {
    if entry.checked_add(16).is_none_or(|end| end > chunk_end) {
        return (
            None,
            Vec::new(),
            Some("resource complex entry header is truncated".into()),
        );
    }
    let parent_id = read_u32_at(bytes, entry + 4).ok();
    let Some(count) = read_u32_at(bytes, entry + 8).ok() else {
        return (
            parent_id,
            Vec::new(),
            Some("resource complex entry count is truncated".into()),
        );
    };
    if count > 100_000 {
        return (
            parent_id,
            Vec::new(),
            Some("resource complex entry count exceeds the maximum".into()),
        );
    }
    let mut values = Vec::with_capacity(count as usize);
    let mut issue = None;
    for index in 0..count as usize {
        let Some(source_offset) = entry
            .checked_add(16)
            .and_then(|start| start.checked_add(index.saturating_mul(12)))
        else {
            issue = Some("resource complex value offset overflows".into());
            break;
        };
        let Some(value_end) = source_offset.checked_add(12) else {
            issue = Some("resource complex value size overflows".into());
            break;
        };
        if value_end > chunk_end || value_end > bytes.len() {
            issue = Some("resource complex value is truncated".into());
            break;
        }
        let key = read_u32_at(bytes, source_offset).unwrap_or_default();
        let value_type = bytes[source_offset + 7];
        let value_size = read_le_u16(bytes, source_offset + 4).ok();
        let value_res0 = bytes.get(source_offset + 6).copied();
        let value_data = read_u32_at(bytes, source_offset + 8).ok();
        let string_pool_index = (value_type == 0x03).then_some(value_data).flatten();
        let decoded_value = value_data.and_then(|data| {
            if value_type == 0x03 {
                global_pool.get(data as usize).map(ToOwned::to_owned)
            } else {
                decode_resource_value(value_type, data)
            }
        });
        let value_issue = if value_type == 0x03 && decoded_value.is_none() {
            Some("resource complex string value is unresolved".into())
        } else if decoded_value.is_none() {
            Some("resource complex value type is unknown".into())
        } else {
            None
        };
        values.push(ResourceComplexValue {
            key,
            key_resource_id: format!("@0x{key:08x}"),
            value_kind: resource_value_kind(value_type).to_owned(),
            value_type: Some(value_type),
            value_data,
            value_size,
            value_res0,
            decoded_value,
            string_pool_index,
            string_pool_source_offset: string_pool_index
                .and_then(|index| string_pool_entry_source_offset(global_pool, index as usize)),
            reference_id: value_data.and_then(|data| resource_reference(value_type, data)),
            source_offset: source_offset as u32,
            issue: value_issue,
        });
    }
    (parent_id, values, issue)
}

fn resource_configuration(bytes: &[u8], offset: usize, size: usize) -> String {
    let mut qualifiers = Vec::new();
    if size >= 8 {
        let mcc = u16::from_le_bytes([
            bytes.get(offset + 4).copied().unwrap_or(0),
            bytes.get(offset + 5).copied().unwrap_or(0),
        ]);
        let mnc = u16::from_le_bytes([
            bytes.get(offset + 6).copied().unwrap_or(0),
            bytes.get(offset + 7).copied().unwrap_or(0),
        ]);
        if mcc != 0 {
            qualifiers.push(format!("mcc{mcc}"));
        }
        if mnc != 0 {
            qualifiers.push(format!("mnc{mnc}"));
        }
    }
    if size >= 12 {
        let language = [
            bytes.get(offset + 8).copied().unwrap_or(0),
            bytes.get(offset + 9).copied().unwrap_or(0),
        ];
        if let Some(language) = decode_packed_locale_language(language) {
            qualifiers.push(language);
        }
        let region = [
            bytes.get(offset + 10).copied().unwrap_or(0),
            bytes.get(offset + 11).copied().unwrap_or(0),
        ];
        if let Some(region) = decode_packed_locale_region(region) {
            qualifiers.push(format!("r{region}"));
        }
    }
    if size >= 44 {
        if let Some(script) = decode_locale_bytes(&bytes[offset + 36..offset + 40]) {
            qualifiers.push(format!("{}", script));
        }
        if let Some(variant) = decode_locale_bytes(&bytes[offset + 40..offset + 44]) {
            qualifiers.push(format!("{}", variant));
        }
    }
    if size >= 16 {
        let density = u16::from_le_bytes([
            bytes.get(offset + 14).copied().unwrap_or(0),
            bytes.get(offset + 15).copied().unwrap_or(0),
        ]);
        if density != 0 {
            qualifiers.push(format!("{}dpi", density));
        }
    }
    if size >= 28 {
        let sdk = u16::from_le_bytes([
            bytes.get(offset + 24).copied().unwrap_or(0),
            bytes.get(offset + 25).copied().unwrap_or(0),
        ]);
        if sdk != 0 {
            qualifiers.push(format!("v{sdk}"));
        }
    }
    append_configuration_qualifier(
        &mut qualifiers,
        bytes.get(offset + 12).copied().unwrap_or(0),
        &[(1, "port"), (2, "land"), (3, "square")],
    );
    append_configuration_qualifier(
        &mut qualifiers,
        bytes.get(offset + 13).copied().unwrap_or(0),
        &[(1, "notouch"), (2, "stylus"), (3, "finger")],
    );
    append_configuration_qualifier(
        &mut qualifiers,
        bytes.get(offset + 16).copied().unwrap_or(0),
        &[(1, "nokeys"), (2, "qwerty"), (3, "12key")],
    );
    append_configuration_qualifier(
        &mut qualifiers,
        bytes.get(offset + 17).copied().unwrap_or(0),
        &[(1, "nonav"), (2, "dpad"), (3, "trackball"), (4, "wheel")],
    );
    if size >= 32 {
        let screen_layout = bytes.get(offset + 28).copied().unwrap_or(0);
        let screen_size = match screen_layout & 0x0f {
            1 => Some("small"),
            2 => Some("normal"),
            3 => Some("large"),
            4 => Some("xlarge"),
            _ => None,
        };
        if let Some(screen_size) = screen_size {
            qualifiers.push(screen_size.into());
        }
        let ui_mode = bytes.get(offset + 29).copied().unwrap_or(0);
        let ui_type = match ui_mode & 0x0f {
            2 => Some("desk"),
            3 => Some("car"),
            4 => Some("television"),
            5 => Some("appliance"),
            6 => Some("watch"),
            7 => Some("vrheadset"),
            _ => None,
        };
        if let Some(ui_type) = ui_type {
            qualifiers.push(ui_type.into());
        }
        if ui_mode & 0x30 == 0x20 {
            qualifiers.push("night".into());
        } else if ui_mode & 0x30 == 0x10 {
            qualifiers.push("notnight".into());
        }
        let smallest_width = u16::from_le_bytes([
            bytes.get(offset + 30).copied().unwrap_or(0),
            bytes.get(offset + 31).copied().unwrap_or(0),
        ]);
        if smallest_width != 0 {
            qualifiers.push(format!("sw{smallest_width}dp"));
        }
    }
    if size >= 36 {
        let width = u16::from_le_bytes([
            bytes.get(offset + 32).copied().unwrap_or(0),
            bytes.get(offset + 33).copied().unwrap_or(0),
        ]);
        let height = u16::from_le_bytes([
            bytes.get(offset + 34).copied().unwrap_or(0),
            bytes.get(offset + 35).copied().unwrap_or(0),
        ]);
        if width != 0 {
            qualifiers.push(format!("w{width}dp"));
        }
        if height != 0 {
            qualifiers.push(format!("h{height}dp"));
        }
    }
    if size >= 46 {
        append_screen_layout_2_qualifiers(&mut qualifiers, bytes[offset + 44]);
        append_color_mode_qualifiers(&mut qualifiers, bytes[offset + 45]);
    }
    if qualifiers.is_empty() {
        "default".into()
    } else {
        qualifiers.join("-")
    }
}

fn append_configuration_qualifier(qualifiers: &mut Vec<String>, value: u8, names: &[(u8, &str)]) {
    if let Some((_, name)) = names.iter().find(|(candidate, _)| *candidate == value) {
        qualifiers.push((*name).into());
    }
}

fn append_screen_layout_2_qualifiers(qualifiers: &mut Vec<String>, value: u8) {
    match value & 0x03 {
        1 => qualifiers.push("notround".into()),
        2 => qualifiers.push("round".into()),
        _ => {}
    }
}

fn append_color_mode_qualifiers(qualifiers: &mut Vec<String>, value: u8) {
    match value & 0x03 {
        1 => qualifiers.push("nowidecg".into()),
        2 => qualifiers.push("widecg".into()),
        _ => {}
    }

    match value & 0x0c {
        0x04 => qualifiers.push("lowdr".into()),
        0x08 => qualifiers.push("highdr".into()),
        _ => {}
    }
}

fn resource_configuration_facts(bytes: &[u8], offset: usize, size: usize) -> ResourceConfiguration {
    let mut facts = ResourceConfiguration {
        size: size as u32,
        source_offset: offset as u32,
        ..ResourceConfiguration::default()
    };
    if size < 4 || offset.saturating_add(size) > bytes.len() {
        facts.issue = Some("resource configuration is truncated".into());
        return facts;
    }
    if size >= 12 {
        facts.mcc = Some(u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]));
        facts.mnc = Some(u16::from_le_bytes([bytes[offset + 6], bytes[offset + 7]]));
        let language = [bytes[offset + 8], bytes[offset + 9]];
        facts.locale = decode_packed_locale_language(language);
        let region = [bytes[offset + 10], bytes[offset + 11]];
        facts.region = decode_packed_locale_region(region);
        facts.locale_raw = Some(bytes[offset + 8..offset + 12].to_vec());
    }
    if size >= 44 {
        let script = &bytes[offset + 36..offset + 40];
        let variant = &bytes[offset + 40..offset + 44];
        facts.locale_script = decode_locale_bytes(script);
        facts.locale_variant = decode_locale_bytes(variant);
    }
    if size >= 16 {
        facts.orientation = Some(bytes[offset + 12]);
        facts.touchscreen = Some(bytes[offset + 13]);
        facts.density = Some(u16::from_le_bytes([bytes[offset + 14], bytes[offset + 15]]));
    }
    if size >= 18 {
        facts.keyboard = Some(bytes[offset + 16]);
        facts.navigation = Some(bytes[offset + 17]);
    }
    if size >= 19 {
        facts.input_flags = Some(bytes[offset + 18]);
    }
    if size >= 24 {
        facts.screen_width = Some(u16::from_le_bytes([bytes[offset + 20], bytes[offset + 21]]));
        facts.screen_height = Some(u16::from_le_bytes([bytes[offset + 22], bytes[offset + 23]]));
    }
    if size >= 28 {
        facts.sdk = Some(u16::from_le_bytes([bytes[offset + 24], bytes[offset + 25]]));
        facts.sdk_minor = Some(u16::from_le_bytes([bytes[offset + 26], bytes[offset + 27]]));
    }
    if size >= 32 {
        facts.screen_layout = Some(bytes[offset + 28]);
        facts.ui_mode = Some(bytes[offset + 29]);
        facts.smallest_width = Some(u16::from_le_bytes([bytes[offset + 30], bytes[offset + 31]]));
    }
    if size >= 36 {
        facts.screen_width_dp = Some(u16::from_le_bytes([bytes[offset + 32], bytes[offset + 33]]));
        facts.screen_height_dp = Some(u16::from_le_bytes([bytes[offset + 34], bytes[offset + 35]]));
    }
    if size >= 46 {
        facts.screen_layout_2 = Some(bytes[offset + 44]);
        facts.color_mode = Some(bytes[offset + 45]);
    }
    facts
}

fn decode_packed_locale_language(bytes: [u8; 2]) -> Option<String> {
    if bytes == [0, 0] {
        return None;
    }
    if bytes[0] & 0x80 != 0 {
        let letters = [
            (bytes[0] & 0x1f) + b'a' - 1,
            (((bytes[0] >> 5) & 0x07) | ((bytes[1] & 0x03) << 3)) + b'a' - 1,
            ((bytes[1] >> 2) & 0x1f) + b'a' - 1,
        ];
        return Some(String::from_utf8_lossy(&letters).into_owned());
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn decode_packed_locale_region(bytes: [u8; 2]) -> Option<String> {
    if bytes == [0, 0] {
        return None;
    }
    if bytes[0] & 0x80 != 0 {
        let digits = [
            ((bytes[0] >> 2) & 0x1f) + b'0',
            (((bytes[0] & 0x03) << 3) | ((bytes[1] >> 5) & 0x07)) + b'0',
            (bytes[1] & 0x1f) + b'0',
        ];
        return Some(String::from_utf8_lossy(&digits).into_owned());
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn decode_locale_bytes(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    (end > 0).then(|| String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn decode_resource_value(value_type: u8, value_data: u32) -> Option<String> {
    match value_type {
        0x00 => decode_null_resource_value(value_data),
        0x04 => Some(f32::from_bits(value_data).to_string()),
        0x05 => decode_complex_resource_value(value_data, &["px", "dp", "sp", "pt", "in", "mm"]),
        0x06 => decode_complex_resource_value(value_data, &["%", "%p"]),
        0x10 => Some((value_data as i32).to_string()),
        0x11 => Some(format!("0x{value_data:08x}")),
        0x12 => Some((value_data != 0).to_string()),
        0x1c..=0x1f => Some(format!("#0x{value_data:08x}")),
        0x01 | 0x02 => None,
        _ => None,
    }
}

fn resource_reference(value_type: u8, value_data: u32) -> Option<String> {
    match value_type {
        0x01 => Some(format!("@0x{value_data:08x}")),
        0x02 => Some(format!("?0x{value_data:08x}")),
        0x07 => Some(format!("@dynamic:0x{value_data:08x}")),
        0x08 => Some(format!("?dynamic:0x{value_data:08x}")),
        _ => None,
    }
}

fn resource_value_kind(value_type: u8) -> &'static str {
    match value_type {
        0x00 => "null",
        0x01 => "reference",
        0x02 => "attribute",
        0x07 => "dynamic_reference",
        0x08 => "dynamic_attribute",
        0x03 => "string",
        0x04 => "float",
        0x05 => "dimension",
        0x06 => "fraction",
        0x10 => "integer",
        0x11 => "hex",
        0x12 => "boolean",
        0x1c..=0x1f => "color",
        _ => "unknown",
    }
}

fn decode_null_resource_value(value_data: u32) -> Option<String> {
    match value_data {
        0 => Some("null".into()),
        1 => Some("undefined".into()),
        _ => None,
    }
}

fn resource_variant_display(
    value_type: u8,
    value_data: u32,
    decoded_value: Option<&str>,
) -> String {
    decoded_value
        .map(str::to_owned)
        .or_else(|| decode_resource_value(value_type, value_data))
        .or_else(|| resource_reference(value_type, value_data))
        .unwrap_or_else(|| format!("0x{value_data:08x}"))
}

fn resource_value_issue(
    value_type: u8,
    value_data: u32,
    decoded_value: Option<&str>,
) -> Option<String> {
    (decoded_value.is_none() && resource_reference(value_type, value_data).is_none())
        .then_some("resource value type is unknown".into())
}

fn decode_complex_resource_value(value_data: u32, units: &[&str]) -> Option<String> {
    let mantissa = (((value_data >> 8) & 0x00ff_ffff) as i32) << 8 >> 8;
    let radix = ((value_data >> 4) & 0x03) as usize;
    let unit = (value_data & 0x0f) as usize;
    let multiplier = [1.0, 1.0 / 128.0, 1.0 / 32768.0, 1.0 / 8_388_608.0][radix];
    let value = mantissa as f64 * multiplier;
    let suffix = units.get(unit)?;
    Some(format!("{value}{suffix}"))
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    if bytes.starts_with(b"<?xml") || bytes.first().is_some_and(|b| *b == b'<') {
        return parse_text_manifest(bytes);
    }
    parse_binary_manifest(bytes)
}

fn parse_text_manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| Error::Malformed("text AndroidManifest.xml is not UTF-8"))?;
    let attr = |tag: &str, key: &str| -> Option<String> {
        let start = find_text_tag_start(&text, 0, tag)?;
        let end = text[start..].find('>')? + start;
        let tail = &text[start..end];
        attr_in(tail, key)
    };
    let mut permissions = Vec::new();
    let mut permission_details = Vec::new();
    let application_label =
        attr("application", "android:label").or_else(|| attr("application", "label"));
    let application_name =
        attr("application", "android:name").or_else(|| attr("application", "name"));
    let application_icon =
        attr("application", "android:icon").or_else(|| attr("application", "icon"));
    let application_round_icon =
        attr("application", "android:roundIcon").or_else(|| attr("application", "roundIcon"));
    let allow_backup = attr("application", "android:allowBackup")
        .or_else(|| attr("application", "allowBackup"))
        .and_then(parse_manifest_bool);
    let extract_native_libs = attr("application", "android:extractNativeLibs")
        .or_else(|| attr("application", "extractNativeLibs"))
        .and_then(parse_manifest_bool);
    let uses_cleartext_traffic = attr("application", "android:usesCleartextTraffic")
        .or_else(|| attr("application", "usesCleartextTraffic"))
        .and_then(parse_manifest_bool);
    let debuggable = attr("application", "android:debuggable")
        .or_else(|| attr("application", "debuggable"))
        .and_then(parse_manifest_bool);
    let mut components: Vec<Component> = Vec::new();
    let mut features = Vec::new();
    let mut supports_screens = SupportsScreens::default();
    let mut cursor = 0;
    while let Some(pos) = text[cursor..].find("<uses-permission") {
        let start = cursor + pos;
        let end = text[start..]
            .find('>')
            .map(|n| start + n)
            .unwrap_or(text.len());
        let tag = &text[start..end];
        let tag_name = tag
            .trim_start_matches('<')
            .split(|character: char| character.is_ascii_whitespace() || character == '>')
            .next()
            .unwrap_or("uses-permission");
        let name = attr_in(tag, "android:name").or_else(|| attr_in(tag, "name"));
        if let Some(name) = name.clone().or_else(|| attr_in(&text[start..end], "name")) {
            permissions.push(name);
        }
        let max_sdk_version =
            attr_in(tag, "android:maxSdkVersion").or_else(|| attr_in(tag, "maxSdkVersion"));
        permission_details.push(PermissionDeclaration {
            tag: tag_name.to_owned(),
            name,
            max_sdk_value: max_sdk_version.as_deref().and_then(parse_sdk_value),
            max_sdk_version,
            uses_permission_flags: attr_in(tag, "android:usesPermissionFlags")
                .or_else(|| attr_in(tag, "usesPermissionFlags")),
            source_offset: start as u32,
        });
        cursor = end.saturating_add(1);
    }
    for kind in [
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    ] {
        let mut cursor = 0;
        while let Some(start) = find_text_tag_start(&text, cursor, kind) {
            let end = text[start..]
                .find('>')
                .map(|n| start + n)
                .unwrap_or(text.len());
            let tag = &text[start..end];
            if let Some(name) = attr_in(tag, "android:name").or_else(|| attr_in(tag, "name")) {
                let exported = attr_in(tag, "android:exported")
                    .or_else(|| attr_in(tag, "exported"))
                    .and_then(parse_manifest_bool);
                let target_activity = attr_in(tag, "android:targetActivity")
                    .or_else(|| attr_in(tag, "targetActivity"));
                let enabled = attr_in(tag, "android:enabled")
                    .or_else(|| attr_in(tag, "enabled"))
                    .and_then(parse_manifest_bool);
                let permission =
                    attr_in(tag, "android:permission").or_else(|| attr_in(tag, "permission"));
                let process = attr_in(tag, "android:process").or_else(|| attr_in(tag, "process"));
                let launch_mode =
                    attr_in(tag, "android:launchMode").or_else(|| attr_in(tag, "launchMode"));
                let theme = attr_in(tag, "android:theme").or_else(|| attr_in(tag, "theme"));
                let intent_filters = parse_text_intent_filters(&text, end, kind);
                components.push(Component {
                    kind: kind.to_owned(),
                    name,
                    exported,
                    target_activity,
                    enabled,
                    permission,
                    process,
                    launch_mode,
                    theme,
                    source_offset: start as u32,
                    intent_filter_count: intent_filters.len(),
                    intent_filters,
                });
            }
            cursor = end.saturating_add(1);
        }
    }
    components.sort_by_key(|component| component.source_offset);
    let mut cursor = 0;
    while let Some(pos) = text[cursor..].find("<uses-feature") {
        let start = cursor + pos;
        let end = text[start..]
            .find('>')
            .map(|n| start + n)
            .unwrap_or(text.len());
        let tag = &text[start..end];
        features.push(UsesFeature {
            name: attr_in(tag, "android:name").or_else(|| attr_in(tag, "name")),
            gl_es_version: attr_in(tag, "android:glEsVersion")
                .or_else(|| attr_in(tag, "glEsVersion")),
            required: attr_in(tag, "android:required")
                .or_else(|| attr_in(tag, "required"))
                .and_then(parse_manifest_bool),
            source_offset: start as u32,
        });
        cursor = end.saturating_add(1);
    }
    if let Some(start) = text.find("<supports-screens") {
        let end = text[start..]
            .find('>')
            .map(|n| start + n)
            .unwrap_or(text.len());
        let tag = &text[start..end];
        supports_screens.source_offset = Some(start as u32);
        supports_screens.small = attr_in(tag, "android:smallScreens").and_then(parse_manifest_bool);
        supports_screens.normal =
            attr_in(tag, "android:normalScreens").and_then(parse_manifest_bool);
        supports_screens.large = attr_in(tag, "android:largeScreens").and_then(parse_manifest_bool);
        supports_screens.xlarge =
            attr_in(tag, "android:xlargeScreens").and_then(parse_manifest_bool);
        supports_screens.any_density =
            attr_in(tag, "android:anyDensity").and_then(parse_manifest_bool);
    }
    let sdk_tag = text
        .find("<uses-sdk")
        .and_then(|start| text[start..].find('>').map(|end| &text[start..start + end]));
    let min_sdk = sdk_tag.and_then(|tag| attr_in(tag, "android:minSdkVersion"));
    let target_sdk = sdk_tag.and_then(|tag| attr_in(tag, "android:targetSdkVersion"));
    let max_sdk = sdk_tag.and_then(|tag| attr_in(tag, "android:maxSdkVersion"));
    let min_sdk_value = min_sdk.as_deref().and_then(parse_sdk_value);
    let target_sdk_value = target_sdk.as_deref().and_then(parse_sdk_value);
    let max_sdk_value = max_sdk.as_deref().and_then(parse_sdk_value);
    let sdk_source_offset = text.find("<uses-sdk").map(|offset| offset as u32);
    let queries = parse_text_queries(&text);
    let uses_libraries = parse_text_libraries(&text, "uses-library");
    let uses_native_libraries = parse_text_libraries(&text, "uses-native-library");
    let uses_configuration = parse_text_uses_configuration(&text);
    Ok(Manifest {
        package_name: attr("manifest", "package"),
        version_name: attr("manifest", "android:versionName"),
        version_code: attr("manifest", "android:versionCode"),
        min_sdk,
        target_sdk,
        max_sdk,
        min_sdk_value,
        target_sdk_value,
        max_sdk_value,
        sdk_source_offset,
        permissions,
        permission_details,
        text,
        binary: false,
        application_label,
        application_name,
        application_icon,
        application_round_icon,
        allow_backup,
        extract_native_libs,
        uses_cleartext_traffic,
        debuggable,
        components,
        features,
        supports_screens,
        queries,
        uses_libraries,
        uses_native_libraries,
        uses_configuration,
    })
}

fn find_text_tag_start(text: &str, cursor: usize, tag_name: &str) -> Option<usize> {
    let marker = format!("<{tag_name}");
    let mut search = cursor;

    while let Some(relative_start) = text[search..].find(&marker) {
        let start = search + relative_start;
        let name_end = start + marker.len();
        let is_exact_tag = text
            .as_bytes()
            .get(name_end)
            .is_none_or(|byte| byte.is_ascii_whitespace() || *byte == b'>' || *byte == b'/');

        if is_exact_tag {
            return Some(start);
        }

        search = name_end;
    }

    None
}

fn parse_text_intent_filters(text: &str, component_end: usize, kind: &str) -> Vec<IntentFilter> {
    let component_body = text[component_end.saturating_add(1)..]
        .find(&format!("</{kind}>"))
        .map(|close| &text[component_end.saturating_add(1)..component_end + 1 + close])
        .unwrap_or("");
    let mut filters = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = component_body[cursor..].find("<intent-filter") {
        let start = cursor + relative_start;
        let Some(open_end) = component_body[start..].find('>') else {
            break;
        };
        let open_end = start + open_end;
        let filter_end = component_body[open_end..]
            .find("</intent-filter>")
            .map(|close| open_end + close)
            .unwrap_or(open_end);
        let filter_body = &component_body[start..filter_end];
        filters.push(IntentFilter {
            actions: text_tag_attribute_values(filter_body, "action", "name"),
            categories: text_tag_attribute_values(filter_body, "category", "name"),
            data_schemes: text_tag_attribute_values(filter_body, "data", "scheme"),
            mime_types: text_tag_attribute_values(filter_body, "data", "mimeType"),
            source_offset: (component_end.saturating_add(1) + start) as u32,
        });
        cursor = if filter_end > start {
            filter_end.saturating_add("</intent-filter>".len())
        } else {
            open_end.saturating_add(1)
        };
    }
    filters
}

fn text_tag_attribute_values(body: &str, tag_name: &str, attribute: &str) -> Vec<String> {
    let marker = format!("<{tag_name}");
    let mut values = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = body[cursor..].find(&marker) {
        let start = cursor + relative_start;
        let name_end = start + marker.len();
        if body
            .as_bytes()
            .get(name_end)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'>' && *byte != b'/')
        {
            cursor = name_end;
            continue;
        }
        let Some(end) = body[start..].find('>') else {
            break;
        };
        let tag = &body[start..start + end];
        if let Some(value) =
            attr_in(tag, &format!("android:{attribute}")).or_else(|| attr_in(tag, attribute))
        {
            values.push(value);
        }
        cursor = start + end + 1;
    }
    values
}

fn parse_text_uses_configuration(text: &str) -> Option<UsesConfiguration> {
    let start = text.find("<uses-configuration")?;
    let end = text[start..].find('>').map(|offset| start + offset)?;
    let tag = &text[start..end];
    Some(UsesConfiguration {
        req_keyboard_type: attr_in(tag, "android:reqKeyboardType")
            .or_else(|| attr_in(tag, "reqKeyboardType")),
        req_keyboard_type_value: attr_in(tag, "android:reqKeyboardType")
            .or_else(|| attr_in(tag, "reqKeyboardType"))
            .and_then(parse_keyboard_type),
        req_navigation: attr_in(tag, "android:reqNavigation")
            .or_else(|| attr_in(tag, "reqNavigation")),
        req_navigation_value: attr_in(tag, "android:reqNavigation")
            .or_else(|| attr_in(tag, "reqNavigation"))
            .and_then(parse_navigation_type),
        req_touchscreen: attr_in(tag, "android:reqTouchScreen")
            .or_else(|| attr_in(tag, "reqTouchScreen")),
        req_touchscreen_value: attr_in(tag, "android:reqTouchScreen")
            .or_else(|| attr_in(tag, "reqTouchScreen"))
            .and_then(parse_touchscreen_type),
        req_five_way_nav: attr_in(tag, "android:reqFiveWayNav")
            .or_else(|| attr_in(tag, "reqFiveWayNav"))
            .and_then(parse_manifest_bool),
        req_hard_keyboard: attr_in(tag, "android:reqHardKeyboard")
            .or_else(|| attr_in(tag, "reqHardKeyboard"))
            .and_then(parse_manifest_bool),
        source_offset: start as u32,
    })
}

fn parse_keyboard_type(value: String) -> Option<String> {
    matches!(value.as_str(), "nokeys" | "qwerty" | "twelvekey").then_some(value)
}

fn parse_navigation_type(value: String) -> Option<String> {
    matches!(value.as_str(), "nonav" | "dpad" | "trackball" | "wheel").then_some(value)
}

fn parse_touchscreen_type(value: String) -> Option<String> {
    matches!(value.as_str(), "notouch" | "stylus" | "finger").then_some(value)
}

fn parse_text_libraries(text: &str, tag_name: &str) -> Vec<LibraryDeclaration> {
    let mut libraries = Vec::new();
    collect_text_query_tags(text, tag_name, 0, |tag, offset| {
        libraries.push(LibraryDeclaration {
            name: attr_in(tag, "android:name").or_else(|| attr_in(tag, "name")),
            required: attr_in(tag, "android:required")
                .or_else(|| attr_in(tag, "required"))
                .and_then(parse_manifest_bool),
            source_offset: offset as u32,
        });
    });
    libraries
}

fn parse_text_queries(text: &str) -> Option<QueryVisibility> {
    let start = find_text_tag_start(text, 0, "queries")?;
    let opening_end = text[start..].find('>')? + start;
    let closing_end = text[opening_end..]
        .find("</queries>")
        .map(|offset| opening_end + offset)
        .unwrap_or(text.len());
    let body = &text[opening_end.saturating_add(1)..closing_end];
    let mut queries = QueryVisibility {
        source_offset: start as u32,
        ..QueryVisibility::default()
    };

    collect_text_query_packages(body, opening_end.saturating_add(1), &mut queries);
    collect_text_query_providers(body, opening_end.saturating_add(1), &mut queries);
    collect_text_query_intents(body, opening_end.saturating_add(1), &mut queries);

    Some(queries)
}

fn collect_text_query_packages(body: &str, body_offset: usize, queries: &mut QueryVisibility) {
    collect_text_query_tags(body, "package", body_offset, |tag, offset| {
        queries.packages.push(QueryPackage {
            name: attr_in(tag, "android:name").or_else(|| attr_in(tag, "name")),
            source_offset: offset as u32,
        });
    });
}

fn collect_text_query_providers(body: &str, body_offset: usize, queries: &mut QueryVisibility) {
    collect_text_query_tags(body, "provider", body_offset, |tag, offset| {
        queries.providers.push(QueryProvider {
            name: attr_in(tag, "android:name").or_else(|| attr_in(tag, "name")),
            authorities: attr_in(tag, "android:authorities")
                .or_else(|| attr_in(tag, "authorities")),
            source_offset: offset as u32,
        });
    });
}

fn collect_text_query_intents(body: &str, body_offset: usize, queries: &mut QueryVisibility) {
    let mut cursor = 0;
    while let Some(relative) = body[cursor..].find("<intent") {
        let start = cursor + relative;
        let name_end = start + "<intent".len();
        if body
            .as_bytes()
            .get(name_end)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'>')
        {
            cursor = name_end;
            continue;
        }
        let opening_end = match body[start..].find('>') {
            Some(end) => start + end,
            None => break,
        };
        let closing_end = body[opening_end..]
            .find("</intent>")
            .map(|offset| opening_end + offset)
            .unwrap_or(body.len());
        let intent_body = &body[opening_end.saturating_add(1)..closing_end];
        let mut intent = QueryIntent {
            source_offset: (body_offset + start) as u32,
            ..QueryIntent::default()
        };
        collect_text_query_values(intent_body, "action", &mut intent.actions);
        collect_text_query_values(intent_body, "category", &mut intent.categories);
        collect_text_query_values_attr(intent_body, "data", "scheme", &mut intent.data_schemes);
        collect_text_query_values_attr(intent_body, "data", "mimeType", &mut intent.mime_types);
        collect_text_query_data(
            intent_body,
            body_offset + opening_end.saturating_add(1),
            &mut intent.data,
        );
        queries.intents.push(intent);
        cursor = closing_end
            .saturating_add("</intent>".len())
            .max(opening_end + 1);
    }
}

fn collect_text_query_data(body: &str, body_offset: usize, values: &mut Vec<QueryData>) {
    collect_text_query_tags(body, "data", body_offset, |tag, offset| {
        let attribute =
            |name: &str| attr_in(tag, &format!("android:{name}")).or_else(|| attr_in(tag, name));
        values.push(QueryData {
            scheme: attribute("scheme"),
            mime_type: attribute("mimeType"),
            host: attribute("host"),
            port: attribute("port"),
            path: attribute("path"),
            path_prefix: attribute("pathPrefix"),
            path_pattern: attribute("pathPattern"),
            path_advanced_pattern: attribute("pathAdvancedPattern"),
            path_suffix: attribute("pathSuffix"),
            source_offset: offset as u32,
        });
    });
}

fn collect_text_query_values(body: &str, tag_name: &str, values: &mut Vec<String>) {
    collect_text_query_tags(body, tag_name, 0, |tag, _| {
        if let Some(value) = attr_in(tag, "android:name").or_else(|| attr_in(tag, "name")) {
            values.push(value);
        }
    });
}

fn collect_text_query_values_attr(
    body: &str,
    tag_name: &str,
    attribute: &str,
    values: &mut Vec<String>,
) {
    collect_text_query_tags(body, tag_name, 0, |tag, _| {
        if let Some(value) =
            attr_in(tag, &format!("android:{attribute}")).or_else(|| attr_in(tag, attribute))
        {
            values.push(value);
        }
    });
}

fn collect_text_query_tags<F>(body: &str, tag_name: &str, body_offset: usize, mut visit: F)
where
    F: FnMut(&str, usize),
{
    let marker = format!("<{tag_name}");
    let mut cursor = 0;
    while let Some(relative) = body[cursor..].find(&marker) {
        let start = cursor + relative;
        let name_end = start + marker.len();
        if body
            .as_bytes()
            .get(name_end)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'>' && *byte != b'/')
        {
            cursor = name_end;
            continue;
        }
        let Some(end) = body[start..].find('>') else {
            break;
        };
        visit(&body[start..start + end], body_offset + start);
        cursor = start + end + 1;
    }
}

fn parse_sdk_value(value: &str) -> Option<u32> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse::<u32>().ok(),
            |hex| u32::from_str_radix(hex, 16).ok(),
        )
}

fn parse_manifest_bool(value: String) -> Option<bool> {
    match value.as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}
fn attr_in(text: &str, key: &str) -> Option<String> {
    let double_quoted = format!("{key}=\"");
    let single_quoted = format!("{key}='");
    let (value_start, quote) = if let Some(position) = text.find(&double_quoted) {
        (position + double_quoted.len(), '"')
    } else {
        let position = text.find(&single_quoted)?;
        (position + single_quoted.len(), '\'')
    };

    Some(decode_xml_entities(
        text[value_start..].split(quote).next()?,
    ))
}

fn decode_xml_entities(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(relative_start) = value[cursor..].find('&') {
        let start = cursor + relative_start;
        decoded.push_str(&value[cursor..start]);
        let Some(relative_end) = value[start..].find(';') else {
            decoded.push_str(&value[start..]);
            return decoded;
        };
        let end = start + relative_end;
        let entity = &value[start + 1..end];
        let replacement = match entity {
            "quot" => Some('"'),
            "apos" => Some('\''),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|digits| u32::from_str_radix(digits, 16).ok())
                .or_else(|| {
                    entity
                        .strip_prefix('#')
                        .and_then(|digits| digits.parse().ok())
                })
                .and_then(char::from_u32),
        };
        if let Some(replacement) = replacement {
            decoded.push(replacement);
        } else {
            decoded.push_str(&value[start..=end]);
        }
        cursor = end + 1;
    }
    decoded.push_str(&value[cursor..]);
    decoded
}

fn qualified_binary_xml_name(
    name: Option<&str>,
    namespace_index: usize,
    namespaces: &[NamespaceBinding],
) -> String {
    let local_name = name.unwrap_or("<unresolved-name>");
    let Some(binding) = namespaces
        .iter()
        .rev()
        .find(|binding| binding.uri_index == namespace_index)
    else {
        return if namespace_index == u32::MAX as usize {
            local_name.to_owned()
        } else {
            format!("{{unknown-namespace:{namespace_index}}}{local_name}")
        };
    };
    format!("{}:{local_name}", binding.prefix)
}

#[derive(Debug, Clone)]
struct NamespaceBinding {
    prefix_index: usize,
    uri_index: usize,
    prefix: String,
}

fn decode_binary_xml_attribute_value(
    value_type: u8,
    value_data: u32,
    raw_text: Option<&str>,
) -> String {
    match value_type {
        0x00 => match value_data {
            0 => "undefined".to_owned(),
            1 => "null".to_owned(),
            _ => format!("<invalid-null:0x{value_data:08x}>"),
        },
        0x01 => format!("@0x{value_data:08x}"),
        0x02 => format!("?0x{value_data:08x}"),
        0x03 => raw_text
            .map(str::to_owned)
            .unwrap_or_else(|| format!("<string-pool:{value_data}>")),
        0x05 => decode_complex_resource_value(value_data, &["px", "dp", "sp", "pt", "in", "mm"])
            .unwrap_or_else(|| format!("<invalid-dimension:0x{value_data:08x}>")),
        0x06 => decode_complex_resource_value(value_data, &["%", "%p"])
            .unwrap_or_else(|| format!("<invalid-fraction:0x{value_data:08x}>")),
        0x10 => (value_data as i32).to_string(),
        0x11 => format!("0x{value_data:08x}"),
        0x12 => (value_data != 0).to_string(),
        0x1c..=0x1f => format!("#0x{value_data:08x}"),
        _ => format!("<unknown-type:0x{value_type:02x}:0x{value_data:08x}>"),
    }
}

fn parse_binary_manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    if bytes.len() < 8 || u16::from_le_bytes(bytes[..2].try_into().unwrap()) != 3 {
        return Err(Error::Unsupported(
            "Android binary XML manifest is unsupported",
        ));
    }
    let pool = StringPool::read(bytes, 8)?;
    let mut package_name = None;
    let mut version_name = None;
    let mut version_code = None;
    let mut min_sdk = None;
    let mut target_sdk = None;
    let mut max_sdk = None;
    let mut min_sdk_value = None;
    let mut target_sdk_value = None;
    let mut max_sdk_value = None;
    let mut sdk_source_offset = None;
    let mut application_label = None;
    let mut application_name = None;
    let mut application_icon = None;
    let mut application_round_icon = None;
    let mut allow_backup = None;
    let mut extract_native_libs = None;
    let mut uses_cleartext_traffic = None;
    let mut debuggable = None;
    let mut permissions = Vec::new();
    let mut permission_details = Vec::new();
    let mut text = String::new();
    let mut components: Vec<Component> = Vec::new();
    let mut last_component: Option<usize> = None;
    let mut last_filter: Option<usize> = None;
    let mut features: Vec<UsesFeature> = Vec::new();
    let mut supports_screens = SupportsScreens::default();
    let mut uses_libraries = Vec::new();
    let mut uses_native_libraries = Vec::new();
    let mut uses_configuration = None;
    let mut queries: Option<QueryVisibility> = None;
    let mut query_depth = 0usize;
    let mut query_intent: Option<usize> = None;
    let mut library_name = None;
    let mut library_required = None;
    let mut namespaces: Vec<NamespaceBinding> = Vec::new();
    let mut offset = 8 + pool.chunk_size;
    while offset + 16 <= bytes.len() {
        let kind = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if size < 8 || offset + size > bytes.len() {
            return Err(Error::Malformed("Android binary XML chunk is truncated"));
        }
        if kind == 0x0101 && size >= 24 {
            let prefix_index = read_u32_at(bytes, offset + 16).unwrap_or(u32::MAX) as usize;
            let uri_index = read_u32_at(bytes, offset + 20).unwrap_or(u32::MAX) as usize;
            if let Some(index) = namespaces.iter().rposition(|binding| {
                binding.prefix_index == prefix_index && binding.uri_index == uri_index
            }) {
                namespaces.remove(index);
            }
            offset += size;
            continue;
        }
        if kind == 0x0103 {
            // END_ELEMENT chunks close only their matching element.  Nested
            // query children and intent-filter members must not collapse the
            // parent scope while they are still being decoded.
            let end_name = read_u32_at(bytes, offset + 20)
                .ok()
                .and_then(|index| pool.get(index as usize))
                .unwrap_or_default();
            match end_name {
                "intent-filter" => last_filter = None,
                "activity" | "activity-alias" | "service" | "receiver"
                    if last_component.is_some() =>
                {
                    last_component = None;
                    last_filter = None;
                }
                "provider" if query_depth > 1 => query_depth = 1,
                "provider" => {
                    last_component = None;
                    last_filter = None;
                }
                "intent" if query_depth > 1 => {
                    query_depth = 1;
                    query_intent = None;
                }
                "package" if query_depth > 1 => query_depth = 1,
                "queries" => {
                    query_depth = 0;
                    query_intent = None;
                }
                _ => {}
            }
            offset += size;
            continue;
        }
        if kind == 0x0100 && size >= 24 {
            let prefix_index = read_u32_at(bytes, offset + 16).unwrap_or(u32::MAX) as usize;
            let uri_index = read_u32_at(bytes, offset + 20).unwrap_or(u32::MAX) as usize;
            if let Some(uri) = pool.get(uri_index) {
                let prefix = pool
                    .get(prefix_index)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{{{uri}}}"));
                namespaces.push(NamespaceBinding {
                    prefix_index,
                    uri_index,
                    prefix,
                });
            }
            offset += size;
            continue;
        }
        if kind == 0x0102 && size >= 36 {
            let element_namespace = read_u32_at(bytes, offset + 16).unwrap_or(u32::MAX) as usize;
            let name_idx = read_u32_at(bytes, offset + 20).unwrap_or(u32::MAX) as usize;
            let name =
                qualified_binary_xml_name(pool.get(name_idx), element_namespace, &namespaces);
            let attr_start =
                u16::from_le_bytes(bytes[offset + 24..offset + 26].try_into().unwrap()) as usize;
            let attr_size =
                u16::from_le_bytes(bytes[offset + 26..offset + 28].try_into().unwrap()) as usize;
            let count =
                u16::from_le_bytes(bytes[offset + 28..offset + 30].try_into().unwrap()) as usize;
            let base = offset + 16 + attr_start;
            text.push('<');
            text.push_str(&name);
            let is_component = matches!(
                name.as_str(),
                "activity" | "activity-alias" | "service" | "receiver" | "provider"
            );
            if is_component {
                last_filter = None;
            }
            let mut component_name = None;
            let mut component_exported = None;
            let mut component_target = None;
            let mut component_enabled = None;
            let mut component_permission = None;
            let mut component_process = None;
            let mut component_launch_mode = None;
            let mut component_theme = None;
            let mut feature_name = None;
            let mut feature_gl_es = None;
            let mut feature_required = None;
            let mut query_name = None;
            let mut query_authorities = None;
            let mut query_data = QueryData {
                source_offset: offset as u32,
                ..QueryData::default()
            };
            let mut permission_name = None;
            let mut permission_max_sdk = None;
            let mut permission_flags = None;
            let mut configuration_keyboard = None;
            let mut configuration_navigation = None;
            let mut configuration_touchscreen = None;
            let mut configuration_five_way = None;
            let mut configuration_hard_keyboard = None;
            for i in 0..count {
                let a = base + i * attr_size;
                if a + 20 > offset + size {
                    return Err(Error::Malformed(
                        "Android binary XML attribute is truncated",
                    ));
                }
                let attribute_namespace = read_u32_at(bytes, a).unwrap_or(u32::MAX) as usize;
                let attribute_name_index = read_u32_at(bytes, a + 4).unwrap_or(u32::MAX) as usize;
                let n = qualified_binary_xml_name(
                    pool.get(attribute_name_index),
                    attribute_namespace,
                    &namespaces,
                );
                let raw = u32::from_le_bytes(bytes[a + 8..a + 12].try_into().unwrap()) as usize;
                let value_type = bytes[a + 15];
                let value_data = u32::from_le_bytes(bytes[a + 16..a + 20].try_into().unwrap());
                let val = decode_binary_xml_attribute_value(value_type, value_data, pool.get(raw));
                if let (Some(component), Some(filter)) = (last_component, last_filter) {
                    let target = &mut components[component].intent_filters[filter];
                    if name == "action" && (n == "name" || n.ends_with(":name")) {
                        target.actions.push(val.clone());
                    }
                    if name == "category" && (n == "name" || n.ends_with(":name")) {
                        target.categories.push(val.clone());
                    }
                    if name == "data" && (n == "scheme" || n.ends_with(":scheme")) {
                        target.data_schemes.push(val.clone());
                    }
                    if name == "data" && (n == "mimeType" || n.ends_with(":mimeType")) {
                        target.mime_types.push(val.clone());
                    }
                }
                if is_component && (n == "name" || n.ends_with(":name")) {
                    component_name = Some(val.clone());
                }
                if is_component && (n == "exported" || n.ends_with(":exported")) {
                    component_exported = parse_manifest_bool(val.clone());
                }
                if is_component && (n == "targetActivity" || n.ends_with(":targetActivity")) {
                    component_target = Some(val.clone());
                }
                if is_component && (n == "enabled" || n.ends_with(":enabled")) {
                    component_enabled = parse_manifest_bool(val.clone());
                }
                if is_component && (n == "permission" || n.ends_with(":permission")) {
                    component_permission = Some(val.clone());
                }
                if is_component && (n == "process" || n.ends_with(":process")) {
                    component_process = Some(val.clone());
                }
                if is_component && (n == "launchMode" || n.ends_with(":launchMode")) {
                    component_launch_mode = Some(val.clone());
                }
                if is_component && (n == "theme" || n.ends_with(":theme")) {
                    component_theme = Some(val.clone());
                }
                if name == "uses-feature" && (n == "name" || n.ends_with(":name")) {
                    feature_name = Some(val.clone());
                }
                if name == "uses-feature" && (n == "glEsVersion" || n.ends_with(":glEsVersion")) {
                    feature_gl_es = Some(val.clone());
                }
                if name == "uses-feature" && (n == "required" || n.ends_with(":required")) {
                    feature_required = parse_manifest_bool(val.clone());
                }
                if name == "supports-screens" {
                    supports_screens.source_offset = Some(offset as u32);
                    let parsed_bool = parse_manifest_bool(val.clone());
                    match n.as_str() {
                        "smallScreens" | "android:smallScreens" => {
                            supports_screens.small = parsed_bool
                        }
                        "normalScreens" | "android:normalScreens" => {
                            supports_screens.normal = parsed_bool
                        }
                        "largeScreens" | "android:largeScreens" => {
                            supports_screens.large = parsed_bool
                        }
                        "xlargeScreens" | "android:xlargeScreens" => {
                            supports_screens.xlarge = parsed_bool
                        }
                        "anyDensity" | "android:anyDensity" => {
                            supports_screens.any_density = parsed_bool
                        }
                        _ => {}
                    }
                }
                if name == "package" && query_depth == 1 && (n == "name" || n.ends_with(":name")) {
                    query_name = Some(val.clone());
                }
                if name == "provider" && query_depth == 1 {
                    if n == "name" || n.ends_with(":name") {
                        query_name = Some(val.clone());
                    }
                    if n == "authorities" || n.ends_with(":authorities") {
                        query_authorities = Some(val.clone());
                    }
                }
                if query_depth > 1 {
                    if let Some(intent_index) = query_intent {
                        if let Some(intent) = queries
                            .as_mut()
                            .and_then(|visibility| visibility.intents.get_mut(intent_index))
                        {
                            if name == "action" && (n == "name" || n.ends_with(":name")) {
                                intent.actions.push(val.clone());
                            }
                            if name == "category" && (n == "name" || n.ends_with(":name")) {
                                intent.categories.push(val.clone());
                            }
                            if name == "data" && (n == "scheme" || n.ends_with(":scheme")) {
                                intent.data_schemes.push(val.clone());
                            }
                            if name == "data" && (n == "mimeType" || n.ends_with(":mimeType")) {
                                intent.mime_types.push(val.clone());
                            }
                        }
                    }
                    if name == "data" {
                        match n.as_str() {
                            "scheme" | "android:scheme" => query_data.scheme = Some(val.clone()),
                            "mimeType" | "android:mimeType" => {
                                query_data.mime_type = Some(val.clone())
                            }
                            "host" | "android:host" => query_data.host = Some(val.clone()),
                            "port" | "android:port" => query_data.port = Some(val.clone()),
                            "path" | "android:path" => query_data.path = Some(val.clone()),
                            "pathPrefix" | "android:pathPrefix" => {
                                query_data.path_prefix = Some(val.clone())
                            }
                            "pathPattern" | "android:pathPattern" => {
                                query_data.path_pattern = Some(val.clone())
                            }
                            "pathAdvancedPattern" | "android:pathAdvancedPattern" => {
                                query_data.path_advanced_pattern = Some(val.clone())
                            }
                            "pathSuffix" | "android:pathSuffix" => {
                                query_data.path_suffix = Some(val.clone())
                            }
                            _ => {}
                        }
                    }
                }
                if name == "application" && (n == "label" || n.ends_with(":label")) {
                    application_label = Some(val.clone());
                }
                if name == "application" && (n == "name" || n.ends_with(":name")) {
                    application_name = Some(val.clone());
                }
                if name == "application" && (n == "icon" || n.ends_with(":icon")) {
                    application_icon = Some(val.clone());
                }
                if name == "application" && (n == "roundIcon" || n.ends_with(":roundIcon")) {
                    application_round_icon = Some(val.clone());
                }
                if name == "application" && (n == "allowBackup" || n.ends_with(":allowBackup")) {
                    allow_backup = parse_manifest_bool(val.clone());
                }
                if name == "application"
                    && (n == "extractNativeLibs" || n.ends_with(":extractNativeLibs"))
                {
                    extract_native_libs = parse_manifest_bool(val.clone());
                }
                if name == "application"
                    && (n == "usesCleartextTraffic" || n.ends_with(":usesCleartextTraffic"))
                {
                    uses_cleartext_traffic = parse_manifest_bool(val.clone());
                }
                if matches!(name.as_str(), "uses-library" | "uses-native-library") {
                    if n == "name" || n.ends_with(":name") {
                        library_name = Some(val.clone());
                    }
                    if n == "required" || n.ends_with(":required") {
                        library_required = parse_manifest_bool(val.clone());
                    }
                }
                if name == "uses-configuration" {
                    match n.as_str() {
                        "reqKeyboardType" | "android:reqKeyboardType" => {
                            configuration_keyboard = Some(val.clone())
                        }
                        "reqNavigation" | "android:reqNavigation" => {
                            configuration_navigation = Some(val.clone())
                        }
                        "reqTouchScreen" | "android:reqTouchScreen" => {
                            configuration_touchscreen = Some(val.clone())
                        }
                        "reqFiveWayNav" | "android:reqFiveWayNav" => {
                            configuration_five_way = parse_manifest_bool(val.clone())
                        }
                        "reqHardKeyboard" | "android:reqHardKeyboard" => {
                            configuration_hard_keyboard = parse_manifest_bool(val.clone())
                        }
                        _ => {}
                    }
                }
                if name == "application" && (n == "debuggable" || n.ends_with(":debuggable")) {
                    debuggable = parse_manifest_bool(val.clone());
                }
                text.push_str(&format!(" {n}=\"{val}\""));
                if name == "manifest" {
                    match n.as_str() {
                        "package" => package_name = Some(val.clone()),
                        "versionName" | "android:versionName" => version_name = Some(val.clone()),
                        "versionCode" | "android:versionCode" => version_code = Some(val.clone()),
                        _ => {}
                    }
                } else if name == "uses-sdk" {
                    sdk_source_offset = Some(offset as u32);
                    match n.as_str() {
                        "minSdkVersion" | "android:minSdkVersion" => {
                            min_sdk_value = parse_sdk_value(&val);
                            min_sdk = Some(val.clone());
                        }
                        "targetSdkVersion" | "android:targetSdkVersion" => {
                            target_sdk_value = parse_sdk_value(&val);
                            target_sdk = Some(val.clone());
                        }
                        "maxSdkVersion" | "android:maxSdkVersion" => {
                            max_sdk_value = parse_sdk_value(&val);
                            max_sdk = Some(val.clone());
                        }
                        _ => {}
                    }
                }
                if matches!(
                    name.as_str(),
                    "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m"
                ) {
                    match n.as_str() {
                        "name" | "android:name" => permission_name = Some(val.clone()),
                        "maxSdkVersion" | "android:maxSdkVersion" => {
                            permission_max_sdk = Some(val.clone())
                        }
                        "usesPermissionFlags" | "android:usesPermissionFlags" => {
                            permission_flags = Some(val.clone())
                        }
                        _ => {}
                    }
                }
            }
            text.push('>');
            if name == "data" && query_depth > 1 {
                if let (Some(visibility), Some(intent_index)) = (queries.as_mut(), query_intent) {
                    if let Some(intent) = visibility.intents.get_mut(intent_index) {
                        intent.data.push(query_data);
                    }
                }
            }
            if name == "uses-library" {
                uses_libraries.push(LibraryDeclaration {
                    name: library_name.take(),
                    required: library_required.take(),
                    source_offset: offset as u32,
                });
            } else if name == "uses-native-library" {
                uses_native_libraries.push(LibraryDeclaration {
                    name: library_name.take(),
                    required: library_required.take(),
                    source_offset: offset as u32,
                });
            } else if matches!(
                name.as_str(),
                "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m"
            ) {
                if let Some(name_value) = permission_name.clone() {
                    permissions.push(name_value);
                }
                permission_details.push(PermissionDeclaration {
                    tag: name.to_owned(),
                    name: permission_name,
                    max_sdk_value: permission_max_sdk.as_deref().and_then(parse_sdk_value),
                    max_sdk_version: permission_max_sdk,
                    uses_permission_flags: permission_flags,
                    source_offset: offset as u32,
                });
            } else if name == "uses-configuration" {
                uses_configuration = Some(UsesConfiguration {
                    req_keyboard_type_value: configuration_keyboard
                        .clone()
                        .and_then(parse_keyboard_type),
                    req_keyboard_type: configuration_keyboard,
                    req_navigation_value: configuration_navigation
                        .clone()
                        .and_then(parse_navigation_type),
                    req_navigation: configuration_navigation,
                    req_touchscreen_value: configuration_touchscreen
                        .clone()
                        .and_then(parse_touchscreen_type),
                    req_touchscreen: configuration_touchscreen,
                    req_five_way_nav: configuration_five_way,
                    req_hard_keyboard: configuration_hard_keyboard,
                    source_offset: offset as u32,
                });
            } else if name == "queries" {
                queries = Some(QueryVisibility {
                    source_offset: offset as u32,
                    ..QueryVisibility::default()
                });
                query_depth = 1;
                query_intent = None;
            } else if query_depth == 1 && name == "package" {
                if let Some(visibility) = queries.as_mut() {
                    visibility.packages.push(QueryPackage {
                        name: query_name,
                        source_offset: offset as u32,
                    });
                }
                query_depth = 2;
            } else if query_depth == 1 && name == "provider" {
                if let Some(visibility) = queries.as_mut() {
                    visibility.providers.push(QueryProvider {
                        name: query_name,
                        authorities: query_authorities,
                        source_offset: offset as u32,
                    });
                }
                query_depth = 2;
            } else if query_depth == 1 && name == "intent" {
                if let Some(visibility) = queries.as_mut() {
                    visibility.intents.push(QueryIntent {
                        source_offset: offset as u32,
                        ..QueryIntent::default()
                    });
                    query_intent = Some(visibility.intents.len() - 1);
                }
                query_depth = 2;
            } else if is_component {
                components.push(Component {
                    kind: name.to_owned(),
                    name: component_name.unwrap_or_default(),
                    exported: component_exported,
                    target_activity: component_target,
                    enabled: component_enabled,
                    permission: component_permission,
                    process: component_process,
                    launch_mode: component_launch_mode,
                    theme: component_theme,
                    source_offset: offset as u32,
                    intent_filter_count: 0,
                    intent_filters: Vec::new(),
                });
                last_component = Some(components.len() - 1);
            } else if name == "uses-feature" {
                features.push(UsesFeature {
                    name: feature_name,
                    gl_es_version: feature_gl_es,
                    required: feature_required,
                    source_offset: offset as u32,
                });
            } else if name == "intent-filter" {
                if let Some(index) = last_component {
                    components[index].intent_filter_count =
                        components[index].intent_filter_count.saturating_add(1);
                    components[index].intent_filters.push(IntentFilter {
                        source_offset: offset as u32,
                        ..IntentFilter::default()
                    });
                    last_filter = Some(components[index].intent_filters.len() - 1);
                }
            }
        }
        offset += size;
    }
    Ok(Manifest {
        package_name,
        version_name,
        version_code,
        min_sdk,
        target_sdk,
        max_sdk,
        min_sdk_value,
        target_sdk_value,
        max_sdk_value,
        sdk_source_offset,
        permissions,
        permission_details,
        text,
        binary: true,
        application_label,
        application_name,
        application_icon,
        application_round_icon,
        allow_backup,
        extract_native_libs,
        uses_cleartext_traffic,
        debuggable,
        components,
        features,
        supports_screens,
        queries,
        uses_libraries,
        uses_native_libraries,
        uses_configuration,
    })
}

struct StringPool {
    values: Vec<String>,
    utf8: bool,
    entry_source_ranges: Vec<(usize, usize)>,
    invalid_utf16: Vec<usize>,
    invalid_utf16_source_offsets: Vec<usize>,
    chunk_size: usize,
    source_offset: u32,
}
impl StringPool {
    fn read(bytes: &[u8], offset: usize) -> Result<Self, Error> {
        if offset + 28 > bytes.len()
            || u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) != 1
        {
            return Err(Error::Malformed(
                "Android binary XML string pool is missing",
            ));
        }
        let header = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let flags = u32::from_le_bytes(bytes[offset + 16..offset + 20].try_into().unwrap());
        let strings =
            u32::from_le_bytes(bytes[offset + 20..offset + 24].try_into().unwrap()) as usize;
        let offsets_end = header
            .checked_add(count.checked_mul(4).ok_or(Error::Resource(
                "Android binary XML string offset table size overflow",
            ))?)
            .ok_or(Error::Resource(
                "Android binary XML string offset table size overflow",
            ))?;
        if offset + size > bytes.len()
            || header < 28
            || offsets_end > size
            || strings + count * 4 > size
        {
            return Err(Error::Malformed(
                "Android binary XML string pool is truncated",
            ));
        }
        // ResStringPool_header uses 0x100 for the UTF-8 encoding flag.
        let utf8 = flags & 0x100 != 0;
        let mut values = Vec::with_capacity(count);
        let mut entry_source_ranges = Vec::with_capacity(count);
        let mut invalid_utf16 = Vec::new();
        let mut invalid_utf16_source_offsets = Vec::new();
        for i in 0..count {
            let at = offset + header + i * 4;
            let rel = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            // AOSP stores `strings` as the offset to the string data. Some
            // older fixtures used the header start and treated each offset as
            // relative to the end of the offset table; accepting both forms
            // keeps source ranges faithful while remaining format-aware.
            let string_data = strings.max(offsets_end);
            let p = offset + string_data + rel;
            let (value, end) = if utf8 {
                let (_, x) = read_len8(bytes, p)?;
                let (n, s) = read_len8(bytes, x)?;
                (
                    String::from_utf8_lossy(&bytes[s..s + n]).into_owned(),
                    s + n,
                )
            } else {
                let (n, s) = read_len16(bytes, p)?;
                let units = bytes[s..s + n]
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<_>>();
                let value = match String::from_utf16(&units) {
                    Ok(value) => value,
                    Err(_) => {
                        invalid_utf16.push(i);
                        invalid_utf16_source_offsets.push(p);
                        String::from_utf16_lossy(&units)
                    }
                };
                (value, s + n)
            };
            values.push(value);
            entry_source_ranges.push((p, end));
        }
        Ok(Self {
            values,
            utf8,
            entry_source_ranges,
            invalid_utf16,
            invalid_utf16_source_offsets,
            chunk_size: size,
            source_offset: offset as u32,
        })
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.values.get(index).map(String::as_str)
    }
}
fn read_len8(bytes: &[u8], at: usize) -> Result<(usize, usize), Error> {
    let first = *bytes
        .get(at)
        .ok_or(Error::Malformed("Android XML string length is truncated"))?;
    if first & 0x80 != 0 {
        let second = *bytes
            .get(at + 1)
            .ok_or(Error::Malformed("Android XML string length is truncated"))?;
        Ok((((first & 0x7f) as usize) << 8 | second as usize, at + 2))
    } else {
        Ok((first as usize, at + 1))
    }
}
fn read_len16(bytes: &[u8], at: usize) -> Result<(usize, usize), Error> {
    let raw = u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(Error::Malformed("Android XML string length is truncated"))?
            .try_into()
            .unwrap(),
    );
    if raw & 0x8000 != 0 {
        let next = u16::from_le_bytes(
            bytes
                .get(at + 2..at + 4)
                .ok_or(Error::Malformed("Android XML string length is truncated"))?
                .try_into()
                .unwrap(),
        );
        Ok((
            (((raw & 0x7fff) as usize) << 16 | next as usize) * 2,
            at + 4,
        ))
    } else {
        Ok((raw as usize * 2, at + 2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_string_pool() -> StringPool {
        StringPool {
            values: Vec::new(),
            utf8: false,
            entry_source_ranges: Vec::new(),
            invalid_utf16: Vec::new(),
            invalid_utf16_source_offsets: Vec::new(),
            chunk_size: 0,
            source_offset: 0,
        }
    }

    #[test]
    fn parses_text_manifest() {
        let m = br#"<manifest package="com.example" android:versionName="1"><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:name=".App" android:icon="@0x7f010001" android:roundIcon="@0x7f010002" android:allowBackup="false" android:extractNativeLibs="true" android:usesCleartextTraffic="false"/></manifest>"#;
        let p = parse_text_manifest(m).unwrap();
        assert_eq!(p.package_name.as_deref(), Some("com.example"));
        assert_eq!(p.permissions, vec!["android.permission.INTERNET"]);
        assert_eq!(p.application_name.as_deref(), Some(".App"));
        assert_eq!(p.application_icon.as_deref(), Some("@0x7f010001"));
        assert_eq!(p.allow_backup, Some(false));
        assert_eq!(p.extract_native_libs, Some(true));
        assert_eq!(p.uses_cleartext_traffic, Some(false));
    }

    #[test]
    fn parses_single_quoted_manifest_attributes() {
        let manifest = br#"<manifest package='com.example'><uses-permission android:name='android.permission.INTERNET'/><application android:label='Single quoted' android:name='.App'/></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert_eq!(parsed.package_name.as_deref(), Some("com.example"));
        assert_eq!(parsed.permissions, vec!["android.permission.INTERNET"]);
        assert_eq!(parsed.application_label.as_deref(), Some("Single quoted"));
        assert_eq!(parsed.application_name.as_deref(), Some(".App"));
    }

    #[test]
    fn root_attribute_lookup_ignores_tag_name_prefixes() {
        let manifest = br#"<manifest-extra package="wrong"><application-extra android:label="wrong"/></manifest-extra><manifest package="com.example"><application-extra android:label="wrong"/><application android:label="right"/></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert_eq!(parsed.package_name.as_deref(), Some("com.example"));
        assert_eq!(parsed.application_label.as_deref(), Some("right"));
    }

    #[test]
    fn preserves_unknown_application_booleans_as_absent() {
        let manifest = br#"<manifest package="com.example"><application android:allowBackup="maybe" android:extractNativeLibs="unknown" android:usesCleartextTraffic="unset" android:debuggable="sometimes"/></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert_eq!(parsed.allow_backup, None);
        assert_eq!(parsed.extract_native_libs, None);
        assert_eq!(parsed.uses_cleartext_traffic, None);
        assert_eq!(parsed.debuggable, None);
    }

    #[test]
    fn parses_sdk_raw_and_decoded_values_with_unknowns() {
        let manifest = br#"<manifest package="com.example"><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="Q" android:maxSdkVersion="35"/></manifest>"#;
        let parsed = parse_text_manifest(manifest).unwrap();
        assert_eq!(parsed.min_sdk.as_deref(), Some("24"));
        assert_eq!(parsed.min_sdk_value, Some(24));
        assert_eq!(parsed.target_sdk.as_deref(), Some("Q"));
        assert_eq!(parsed.target_sdk_value, None);
        assert_eq!(parsed.max_sdk.as_deref(), Some("35"));
        assert_eq!(parsed.max_sdk_value, Some(35));
        assert!(parsed.sdk_source_offset.is_some());
    }

    #[test]
    fn parses_hex_sdk_values_and_decodes_manifest_entities() {
        let manifest = br#"<manifest package="com.example&amp;co"><uses-sdk android:minSdkVersion="0x18"/><application android:label="A &amp; B &#x1F600;"/></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert_eq!(parsed.package_name.as_deref(), Some("com.example&co"));
        assert_eq!(parsed.min_sdk_value, Some(24));
        assert_eq!(parsed.application_label.as_deref(), Some("A & B 😀"));
    }

    #[test]
    fn preserves_unknown_manifest_entities() {
        assert_eq!(
            decode_xml_entities("A &unknown; B &broken"),
            "A &unknown; B &broken"
        );
    }

    #[test]
    fn parses_library_declarations_and_unknown_required_values() {
        let manifest = br#"<manifest package="com.example"><application/><uses-library android:name="com.example.shared" android:required="false"/><uses-native-library android:name="com.example.native" android:required="maybe"/></manifest>"#;
        let parsed = parse_text_manifest(manifest).unwrap();
        assert_eq!(parsed.uses_libraries.len(), 1);
        assert_eq!(
            parsed.uses_libraries[0].name.as_deref(),
            Some("com.example.shared")
        );
        assert_eq!(parsed.uses_libraries[0].required, Some(false));
        assert_eq!(parsed.uses_native_libraries.len(), 1);
        assert_eq!(
            parsed.uses_native_libraries[0].name.as_deref(),
            Some("com.example.native")
        );
        assert_eq!(parsed.uses_native_libraries[0].required, None);
        assert!(
            parsed.uses_libraries[0].source_offset < parsed.uses_native_libraries[0].source_offset
        );
    }

    #[test]
    fn ignores_manifest_tags_with_library_name_prefixes() {
        let manifest = br#"<manifest package="com.example"><uses-library-extra android:name="wrong"/><uses-library android:name="right"/></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert_eq!(parsed.uses_libraries.len(), 1);
        assert_eq!(parsed.uses_libraries[0].name.as_deref(), Some("right"));
    }

    #[test]
    fn parses_sdk_scoped_permissions_and_raw_flags() {
        let manifest = br#"<manifest package="com.example"><uses-permission android:name="a" android:maxSdkVersion="32" android:usesPermissionFlags="neverForLocation"/><uses-permission-sdk-23 android:name="b" android:maxSdkVersion="Q"/><uses-permission-sdk-m android:name="c"/></manifest>"#;
        let parsed = parse_text_manifest(manifest).unwrap();
        assert_eq!(parsed.permission_details.len(), 3);
        assert_eq!(parsed.permission_details[0].tag, "uses-permission");
        assert_eq!(parsed.permission_details[0].max_sdk_value, Some(32));
        assert_eq!(
            parsed.permission_details[0]
                .uses_permission_flags
                .as_deref(),
            Some("neverForLocation")
        );
        assert_eq!(parsed.permission_details[1].tag, "uses-permission-sdk-23");
        assert_eq!(
            parsed.permission_details[1].max_sdk_version.as_deref(),
            Some("Q")
        );
        assert_eq!(parsed.permission_details[1].max_sdk_value, None);
        assert_eq!(parsed.permissions, vec!["a", "b", "c"]);
    }

    #[test]
    fn preserves_manifest_permission_order_and_duplicates() {
        let manifest = br#"<manifest package="com.example"><uses-permission android:name="b"/><uses-permission android:name="a"/><uses-permission android:name="b"/></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert_eq!(parsed.permissions, vec!["b", "a", "b"]);
    }

    #[test]
    fn malformed_permission_keeps_unknown_name_without_inventing_one() {
        let manifest = br#"<manifest package="com.example"><uses-permission android:maxSdkVersion="33"/></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert!(parsed.permissions.is_empty());
        assert_eq!(parsed.permission_details.len(), 1);
        assert!(parsed.permission_details[0].name.is_none());
        assert_eq!(parsed.permission_details[0].max_sdk_value, Some(33));
    }

    #[test]
    fn parses_uses_configuration_with_unknown_values_preserved() {
        let manifest = br#"<manifest package="com.example"><uses-configuration android:reqKeyboardType="qwerty" android:reqNavigation="mystery" android:reqTouchScreen="finger" android:reqFiveWayNav="true" android:reqHardKeyboard="maybe"/></manifest>"#;
        let parsed = parse_text_manifest(manifest).unwrap();
        let configuration = parsed.uses_configuration.unwrap();
        assert_eq!(configuration.req_keyboard_type.as_deref(), Some("qwerty"));
        assert_eq!(
            configuration.req_keyboard_type_value.as_deref(),
            Some("qwerty")
        );
        assert_eq!(configuration.req_navigation.as_deref(), Some("mystery"));
        assert_eq!(configuration.req_navigation_value, None);
        assert_eq!(
            configuration.req_touchscreen_value.as_deref(),
            Some("finger")
        );
        assert_eq!(configuration.req_five_way_nav, Some(true));
        assert_eq!(configuration.req_hard_keyboard, None);
        assert!(configuration.source_offset > 0);
    }

    #[test]
    fn parses_component_alias_attributes_without_defaults() {
        let manifest = br#"<manifest package="com.example"><application><activity-alias android:name=".Alias" android:targetActivity=".Main" android:enabled="false" android:permission="com.example.P" android:process=":remote" android:launchMode="singleTop" android:theme="@0x7f010001"/></application></manifest>"#;
        let parsed = parse_text_manifest(manifest).unwrap();
        assert_eq!(parsed.components.len(), 1);
        let component = parsed.components.first().unwrap();
        assert_eq!(component.kind, "activity-alias");
        assert_eq!(component.target_activity.as_deref(), Some(".Main"));
        assert_eq!(component.enabled, Some(false));
        assert_eq!(component.permission.as_deref(), Some("com.example.P"));
        assert_eq!(component.process.as_deref(), Some(":remote"));
        assert_eq!(component.launch_mode.as_deref(), Some("singleTop"));
        assert_eq!(component.theme.as_deref(), Some("@0x7f010001"));
        assert_eq!(component.exported, None);
    }

    #[test]
    fn preserves_unknown_text_component_booleans_as_absent() {
        let manifest = br#"<manifest package="com.example"><application><activity android:name=".Main" android:enabled="maybe" android:exported="unset"/></application></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();
        let component = parsed.components.first().unwrap();

        assert_eq!(component.enabled, None);
        assert_eq!(component.exported, None);
    }

    #[test]
    fn preserves_text_component_declaration_order_across_kinds() {
        let manifest = br#"<manifest package="com.example"><application><service android:name=".Worker"/><activity android:name=".Main"/><receiver android:name=".Boot"/></application></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();

        assert_eq!(
            parsed
                .components
                .iter()
                .map(|component| component.name.as_str())
                .collect::<Vec<_>>(),
            vec![".Worker", ".Main", ".Boot"]
        );
        assert!(
            parsed
                .components
                .windows(2)
                .all(|components| components[0].source_offset < components[1].source_offset)
        );
    }

    #[test]
    fn parses_text_component_intent_filter_facts() {
        let manifest = br#"<manifest package="com.example"><application><activity android:name=".Main"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="https" android:mimeType="text/plain"/></intent-filter></activity></application></manifest>"#;

        let parsed = parse_text_manifest(manifest).unwrap();
        let component = parsed.components.first().unwrap();

        assert_eq!(component.intent_filter_count, 1);
        assert_eq!(component.intent_filters.len(), 1);
        assert!(component.intent_filters[0].source_offset > component.source_offset);
        assert_eq!(
            component.intent_filters[0].actions,
            vec!["android.intent.action.VIEW"]
        );
        assert_eq!(
            component.intent_filters[0].categories,
            vec!["android.intent.category.DEFAULT"]
        );
        assert_eq!(component.intent_filters[0].data_schemes, vec!["https"]);
        assert_eq!(component.intent_filters[0].mime_types, vec!["text/plain"]);
    }

    #[test]
    fn parses_features_and_supports_screens_with_offsets() {
        let manifest = br#"<manifest package="com.example"><uses-feature android:name="android.hardware.camera" android:required="false"/><uses-feature android:glEsVersion="0x00020000"/><supports-screens android:smallScreens="true" android:anyDensity="maybe"/></manifest>"#;
        let parsed = parse_text_manifest(manifest).unwrap();
        assert_eq!(parsed.features.len(), 2);
        assert_eq!(parsed.features[0].required, Some(false));
        assert_eq!(
            parsed.features[1].gl_es_version.as_deref(),
            Some("0x00020000")
        );
        assert!(parsed.features[0].source_offset > 0);
        assert_eq!(parsed.supports_screens.small, Some(true));
        assert_eq!(parsed.supports_screens.any_density, None);
        assert!(parsed.supports_screens.source_offset.is_some());
    }

    #[test]
    fn parses_queries_with_nested_visibility_declarations() {
        let manifest = br#"<manifest package="com.example"><queries><package android:name="com.other"/><provider android:authorities="com.other.files"/><intent><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="https" android:mimeType="text/plain" android:host="example.test" android:port="443" android:path="/one" android:pathPrefix="/prefix" android:pathPattern="/.*" android:pathAdvancedPattern="/[a-z]+" android:pathSuffix="/tail"/></intent></queries></manifest>"#;
        let parsed = parse_text_manifest(manifest).unwrap();
        let queries = parsed.queries.as_ref().unwrap();
        assert_eq!(queries.packages[0].name.as_deref(), Some("com.other"));
        assert_eq!(
            queries.providers[0].authorities.as_deref(),
            Some("com.other.files")
        );
        assert_eq!(
            queries.intents[0].actions,
            vec!["android.intent.action.VIEW"]
        );
        assert_eq!(
            queries.intents[0].categories,
            vec!["android.intent.category.DEFAULT"]
        );
        assert_eq!(queries.intents[0].data_schemes, vec!["https"]);
        assert_eq!(queries.intents[0].mime_types, vec!["text/plain"]);
        let data = &queries.intents[0].data[0];
        assert_eq!(data.host.as_deref(), Some("example.test"));
        assert_eq!(data.port.as_deref(), Some("443"));
        assert_eq!(data.path.as_deref(), Some("/one"));
        assert_eq!(data.path_prefix.as_deref(), Some("/prefix"));
        assert_eq!(data.path_pattern.as_deref(), Some("/.*"));
        assert_eq!(data.path_advanced_pattern.as_deref(), Some("/[a-z]+"));
        assert_eq!(data.path_suffix.as_deref(), Some("/tail"));
        assert!(queries.source_offset > 0);
        assert!(queries.intents[0].source_offset > queries.source_offset);
    }

    #[test]
    fn absent_queries_remains_distinct_from_empty_queries() {
        assert!(
            parse_text_manifest(br#"<manifest package="com.example"/>"#)
                .unwrap()
                .queries
                .is_none()
        );
        let parsed =
            parse_text_manifest(br#"<manifest package="com.example"><queries/></manifest>"#)
                .unwrap();
        let queries = parsed.queries.unwrap();
        assert!(queries.packages.is_empty());
        assert!(queries.providers.is_empty());
        assert!(queries.intents.is_empty());
    }

    #[test]
    fn ignores_query_tags_with_prefixes() {
        let parsed = parse_text_manifest(
            br#"<manifest package="com.example"><queries-extra><package android:name="wrong"/></queries-extra></manifest>"#,
        )
        .unwrap();

        assert!(parsed.queries.is_none());
    }

    #[test]
    fn parses_binary_queries_package_declaration() {
        fn chunk(kind: u16, size: usize) -> Vec<u8> {
            let mut bytes = vec![0; size];
            bytes[0..2].copy_from_slice(&kind.to_le_bytes());
            bytes[2..4].copy_from_slice(&8u16.to_le_bytes());
            bytes[4..8].copy_from_slice(&(size as u32).to_le_bytes());
            bytes
        }

        let strings = ["queries", "package", "name", "com.other"];
        let mut pool_data = Vec::new();
        let mut string_offsets = Vec::new();
        for value in strings {
            string_offsets.push(pool_data.len() as u32);
            pool_data.push(value.len() as u8);
            pool_data.push(value.len() as u8);
            pool_data.extend_from_slice(value.as_bytes());
            pool_data.push(0);
        }
        let pool_size = 28 + string_offsets.len() * 4 + pool_data.len();
        let mut pool = chunk(1, pool_size);
        pool[2..4].copy_from_slice(&28u16.to_le_bytes());
        pool[8..12].copy_from_slice(&(string_offsets.len() as u32).to_le_bytes());
        pool[16..20].copy_from_slice(&0x100u32.to_le_bytes());
        pool[20..24].copy_from_slice(&(28u32 + string_offsets.len() as u32 * 4).to_le_bytes());
        for (index, value) in string_offsets.iter().enumerate() {
            let start = 28 + index * 4;
            pool[start..start + 4].copy_from_slice(value.to_le_bytes().as_ref());
        }
        pool[28 + string_offsets.len() * 4..].copy_from_slice(&pool_data);

        let start_tag = |name_index: u32, attribute: Option<(u32, u32)>| {
            let size = if attribute.is_some() { 56 } else { 36 };
            let mut tag = chunk(0x0102, size);
            tag[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
            tag[20..24].copy_from_slice(&name_index.to_le_bytes());
            tag[24..26].copy_from_slice(&20u16.to_le_bytes());
            tag[26..28].copy_from_slice(&20u16.to_le_bytes());
            if let Some((attribute_name, value)) = attribute {
                tag[28..30].copy_from_slice(&1u16.to_le_bytes());
                tag[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
                tag[40..44].copy_from_slice(&attribute_name.to_le_bytes());
                tag[44..48].copy_from_slice(&value.to_le_bytes());
                tag[51] = 3;
                tag[52..56].copy_from_slice(&value.to_le_bytes());
            }
            tag
        };
        let mut bytes = chunk(3, 8);
        bytes.extend_from_slice(&pool);
        bytes.extend_from_slice(&start_tag(0, None));
        bytes.extend_from_slice(&start_tag(1, Some((2, 3))));
        bytes.extend_from_slice(&chunk(0x0103, 16));
        bytes.extend_from_slice(&chunk(0x0103, 16));
        let total_size = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&total_size.to_le_bytes());

        let parsed = parse_binary_manifest(&bytes).unwrap();
        let queries = parsed.queries.unwrap();
        assert_eq!(queries.packages[0].name.as_deref(), Some("com.other"));
        assert!(queries.source_offset > 0);
    }

    #[test]
    fn binary_permission_declaration_is_recorded_once() {
        fn chunk(kind: u16, size: usize) -> Vec<u8> {
            let mut bytes = vec![0; size];
            bytes[0..2].copy_from_slice(&kind.to_le_bytes());
            bytes[2..4].copy_from_slice(&8u16.to_le_bytes());
            bytes[4..8].copy_from_slice(&(size as u32).to_le_bytes());
            bytes
        }

        let strings = [
            "manifest",
            "uses-permission",
            "name",
            "android.permission.INTERNET",
        ];
        let mut pool_data = Vec::new();
        let mut string_offsets = Vec::new();
        for value in strings {
            string_offsets.push(pool_data.len() as u32);
            pool_data.push(value.len() as u8);
            pool_data.push(value.len() as u8);
            pool_data.extend_from_slice(value.as_bytes());
            pool_data.push(0);
        }
        let pool_size = 28 + string_offsets.len() * 4 + pool_data.len();
        let mut pool = chunk(1, pool_size);
        pool[2..4].copy_from_slice(&28u16.to_le_bytes());
        pool[8..12].copy_from_slice(&(string_offsets.len() as u32).to_le_bytes());
        pool[16..20].copy_from_slice(&0x100u32.to_le_bytes());
        pool[20..24].copy_from_slice(&(28u32 + string_offsets.len() as u32 * 4).to_le_bytes());
        for (index, value) in string_offsets.iter().enumerate() {
            let start = 28 + index * 4;
            pool[start..start + 4].copy_from_slice(value.to_le_bytes().as_ref());
        }
        pool[28 + string_offsets.len() * 4..].copy_from_slice(&pool_data);

        let start_tag = |name_index: u32, attribute: Option<(u32, u32)>| {
            let size = if attribute.is_some() { 56 } else { 36 };
            let mut tag = chunk(0x0102, size);
            tag[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
            tag[20..24].copy_from_slice(&name_index.to_le_bytes());
            tag[24..26].copy_from_slice(&20u16.to_le_bytes());
            tag[26..28].copy_from_slice(&20u16.to_le_bytes());
            if let Some((attribute_name, value)) = attribute {
                tag[28..30].copy_from_slice(&1u16.to_le_bytes());
                tag[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
                tag[40..44].copy_from_slice(&attribute_name.to_le_bytes());
                tag[44..48].copy_from_slice(&value.to_le_bytes());
                tag[51] = 3;
                tag[52..56].copy_from_slice(&value.to_le_bytes());
            }
            tag
        };

        let mut bytes = chunk(3, 8);
        bytes.extend_from_slice(&pool);
        bytes.extend_from_slice(&start_tag(0, None));
        bytes.extend_from_slice(&start_tag(1, Some((2, 3))));
        bytes.extend_from_slice(&chunk(0x0103, 16));
        bytes.extend_from_slice(&chunk(0x0103, 16));
        let total_size = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&total_size.to_le_bytes());

        let parsed = parse_binary_manifest(&bytes).unwrap();
        assert_eq!(parsed.permissions, vec!["android.permission.INTERNET"]);
        assert_eq!(parsed.permission_details.len(), 1);
    }

    #[test]
    fn class_data_preserves_delta_encoded_ownership() {
        // sizes: static=0, instance=1, direct=1, virtual=1
        let bytes = [0u8, 0, 1, 1, 1, 3, 0, 7, 0, 2, 1, 0, 0];
        let (fields, methods, code_offsets, static_fields) = read_class_data(&bytes, 1).unwrap();
        assert_eq!(fields, vec![3]);
        assert_eq!(methods, vec![7, 8]);
        assert_eq!(code_offsets, vec![2, 0]);
        assert!(static_fields.is_empty());
    }

    #[test]
    fn empty_type_list_is_unknown_without_claiming_interfaces() {
        let types = vec!["LExample;".to_owned()];
        assert!(read_type_list(&[], 0, &types).unwrap().is_empty());
    }

    #[test]
    fn truncated_class_data_is_rejected() {
        let error = read_class_data(&[0, 1, 1, 1], 1).unwrap_err();
        assert!(matches!(error, Error::Malformed(_)));
    }

    #[test]
    fn oversized_class_data_is_bounded() {
        let error = read_class_data(&[0, 0x80, 0x9a, 0x0c, 0, 0, 0], 1).unwrap_err();
        assert!(matches!(error, Error::Resource(_)));
    }

    #[test]
    fn decodes_code_item_string_and_invoke_edges() {
        let mut bytes = vec![0u8; 32];
        bytes[12..16].copy_from_slice(&5u32.to_le_bytes());
        // const-string v0, string@1; invoke-virtual {v0}, method@2
        bytes[16..24].copy_from_slice(&[0x1a, 0x00, 0x01, 0x00, 0x6e, 0x00, 0x02, 0x00]);
        let strings = vec!["unused".into(), "hello".into()];
        let methods = vec![DexMethod {
            class_descriptor: "LExample;".into(),
            name: "call".into(),
            descriptor: "()V".into(),
        }];
        let decoded = decode_code_item_with_references(&bytes, 0, 7, &strings, &[], &[], &methods);
        assert!(decoded.issues.is_empty());
        assert_eq!(decoded.strings[0].code_unit_offset, 0);
        assert_eq!(decoded.strings[0].value.as_deref(), Some("hello"));
        assert_eq!(decoded.invokes[0].code_unit_offset, 2);
        assert_eq!(decoded.invokes[0].method_index, 2);
        assert!(decoded.invokes[0].target.is_none());
    }

    #[test]
    fn projects_bounded_class_field_and_method_reference_edges() {
        let mut bytes = vec![0u8; 32];
        bytes[12..16].copy_from_slice(&8u32.to_le_bytes());
        // const-class v0, type@0; iget v0, v1, field@0; invoke-virtual {v0}, method@0
        bytes[16..32].copy_from_slice(&[
            0x1c, 0x00, 0x00, 0x00, 0x52, 0x10, 0x00, 0x00, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);

        let types = vec!["LExample;".to_owned()];
        let fields = vec![(
            "LExample;".to_owned(),
            DexField {
                index: 0,
                name: "value".to_owned(),
                field_type: "I".to_owned(),
            },
        )];
        let methods = vec![DexMethod {
            class_descriptor: "LExample;".to_owned(),
            name: "call".to_owned(),
            descriptor: "()V".to_owned(),
        }];

        let decoded =
            decode_code_item_with_references(&bytes, 0, 0, &[], &types, &fields, &methods);

        assert!(decoded.issues.is_empty());
        assert_eq!(decoded.classes[0].target.as_deref(), Some("LExample;"));
        assert_eq!(
            decoded.fields[0].target.as_deref(),
            Some("LExample;->value:I")
        );
        assert_eq!(
            decoded.invokes[0].target.as_deref(),
            Some("LExample;->call()V")
        );

        let references = reference_edges_for_code("classes.dex", &decoded, &methods);
        assert_eq!(references.len(), 3);
        assert!(
            references
                .iter()
                .all(|reference| reference.status == "known")
        );
        assert_eq!(references[0].kind, "method");
        assert_eq!(references[0].source_offset, 26);
        assert_eq!(references[1].kind, "class");
        assert_eq!(references[1].source_offset, 16);
        assert_eq!(references[2].kind, "field");
        assert_eq!(references[2].source_offset, 20);
        assert_eq!(references[0].dex_entry, "classes.dex");
    }

    #[test]
    fn unresolved_reference_edges_preserve_caller_and_unknown_status() {
        let decoded = DexMethodCode {
            method_index: 7,
            code_offset: 100,
            invokes: vec![DexInvokeEdge {
                code_unit_offset: 2,
                method_index: 99,
                target: None,
            }],
            ..DexMethodCode::default()
        };
        let methods = vec![DexMethod {
            class_descriptor: "LCaller;".to_owned(),
            name: "run".to_owned(),
            descriptor: "()V".to_owned(),
        }];

        let references = reference_edges_for_code("classes2.dex", &decoded, &methods);

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].status, "unknown");
        assert_eq!(references[0].target, None);
        assert_eq!(references[0].caller, None);
        assert_eq!(references[0].source_offset, 120);
    }

    #[test]
    fn decodes_method_header_instructions_and_try_handlers() {
        let mut bytes = vec![0u8; 31];
        bytes[0..2].copy_from_slice(&3u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        // nop; nop
        bytes[16..20].copy_from_slice(&[0, 0, 0, 0]);
        // try_item: start_addr=0, insn_count=2, handler_off=0
        bytes[20..28].copy_from_slice(&[0, 0, 0, 0, 2, 0, 0, 0]);
        // encoded_catch_handler_list: size=1, type@0, address=1
        bytes[28..31].copy_from_slice(&[1, 0, 1]);

        let decoded = decode_code_item_with_references(
            &bytes,
            0,
            0,
            &[],
            &["Ljava/lang/Exception;".to_owned()],
            &[],
            &[],
        );

        assert!(decoded.issues.is_empty());
        assert_eq!(decoded.registers_size, Some(3));
        assert_eq!(decoded.ins_size, Some(1));
        assert_eq!(decoded.outs_size, Some(1));
        assert_eq!(decoded.insns_size, Some(2));
        assert_eq!(decoded.instructions.len(), 2);
        assert_eq!(decoded.instructions[1].source_offset, 18);
        assert_eq!(decoded.tries.len(), 1);
        assert_eq!(decoded.tries[0].source_offset, 20);
        assert_eq!(decoded.tries[0].start_code_unit, 0);
        assert_eq!(decoded.tries[0].handlers.len(), 1);
        assert_eq!(
            decoded.tries[0].handlers[0].type_descriptor.as_deref(),
            Some("Ljava/lang/Exception;")
        );
        assert_eq!(decoded.tries[0].handlers[0].address, 1);
    }

    #[test]
    fn malformed_code_item_keeps_partial_issue() {
        let mut bytes = vec![0u8; 18];
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        bytes[16..18].copy_from_slice(&0x001au16.to_le_bytes());
        let decoded = decode_code_item_with_references(&bytes, 0, 0, &[], &[], &[], &[]);
        assert!(
            decoded
                .issues
                .iter()
                .any(|issue| issue.contains("truncated"))
        );
    }

    #[test]
    fn resource_resolution_keeps_unresolved_ids_raw() {
        let manifest = Manifest {
            package_name: None,
            version_name: Some("@0x7f010001".into()),
            version_code: None,
            min_sdk: None,
            target_sdk: None,
            max_sdk: None,
            min_sdk_value: None,
            target_sdk_value: None,
            max_sdk_value: None,
            sdk_source_offset: None,
            application_label: Some("@0x7f010002".into()),
            application_name: None,
            application_icon: None,
            application_round_icon: None,
            allow_backup: None,
            extract_native_libs: None,
            uses_cleartext_traffic: None,
            debuggable: None,
            permissions: vec!["@0x7f010003".into()],
            permission_details: Vec::new(),
            text: String::new(),
            binary: true,
            components: Vec::new(),
            features: Vec::new(),
            supports_screens: SupportsScreens::default(),
            queries: None,
            uses_libraries: Vec::new(),
            uses_native_libraries: Vec::new(),
            uses_configuration: None,
        };
        let mut resources = ResourceTable::default();
        resources.unique.insert("@0x7f010001".into(), "1.2".into());
        let resolved = resolve_manifest_resources(manifest, Some(&resources));
        assert_eq!(resolved.version_name.as_deref(), Some("1.2"));
        assert_eq!(resolved.application_label.as_deref(), Some("@0x7f010002"));
        assert_eq!(resolved.permissions, vec!["@0x7f010003"]);
    }

    #[test]
    fn decodes_debug_lines_parameters_and_local_ranges() {
        let mut bytes = vec![0u8; 48];
        bytes[8..12].copy_from_slice(&32u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        // line_start=10, parameters_size=1, parameter name string index 1,
        // start_local register 0/name 1/type 1, advance_pc 1, end_local, end.
        bytes[32..44].copy_from_slice(&[10, 1, 2, 3, 0, 2, 2, 1, 1, 0, 0x05, 0]);
        let strings = vec!["unused".into(), "value".into()];
        let decoded = decode_code_item_with_references(&bytes, 0, 0, &strings, &[], &[], &[]);
        let debug = decoded.debug.expect("debug info");
        assert_eq!(debug.line_start, 10);
        assert_eq!(debug.parameters, vec![Some("value".into())]);
        assert_eq!(debug.locals.len(), 1);
        assert_eq!(debug.locals[0].end_code_unit, Some(1));
    }

    #[test]
    fn decodes_annotation_visibility_and_string_element() {
        let mut bytes = vec![0u8; 24];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&8u32.to_le_bytes());
        bytes[8..13].copy_from_slice(&[1, 0, 1, 0, 0x17]);
        bytes[13] = 1;
        let annotations = parse_annotation_set(
            &bytes,
            0,
            "LExample;".into(),
            &["LAnno;".into()],
            &["name".into(), "value".into()],
        );
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0].visibility, "runtime");
        assert_eq!(annotations[0].type_descriptor.as_deref(), Some("LAnno;"));
        assert_eq!(annotations[0].elements[0].source_offset, 11);
        assert!(
            matches!(annotations[0].elements[0].value, DexEncodedValue::String(Some(ref value)) if value == "value")
        );
    }

    #[test]
    fn decodes_annotation_enum_array_and_nested_values_with_offsets() {
        let bytes = [
            0x1b, 0x00, // enum string index 0
            0x1c, 0x02, // array with two values
            0x1f, // false
            0x3f, // true
            0x1d, 0x00, 0x01, 0x00, 0x1e, // nested annotation, type 0, one null element
        ];
        let strings = vec!["ENUM_VALUE".to_owned(), "element".to_owned()];
        let types = vec!["LNested;".to_owned()];
        let mut cursor = 0;

        let enum_value =
            decode_annotation_value(&bytes, &mut cursor, &strings, &types, 0).expect("enum value");
        assert!(matches!(
            enum_value,
            DexEncodedValue::Enum {
                index: 0,
                name: Some(ref name),
                source_offset: 0
            } if name == "ENUM_VALUE"
        ));
        let array =
            decode_annotation_value(&bytes, &mut cursor, &strings, &types, 0).expect("array value");
        assert!(matches!(array, DexEncodedValue::Array(values) if values.len() == 2));
        let nested = decode_annotation_value(&bytes, &mut cursor, &strings, &types, 0)
            .expect("nested annotation");
        assert!(matches!(
            nested,
            DexEncodedValue::Annotation {
                type_descriptor: Some(ref descriptor),
                elements
            } if descriptor == "LNested;" && elements.len() == 1 && elements[0].source_offset == 9
        ));
        assert_eq!(cursor, bytes.len());
    }

    #[test]
    fn decodes_call_sites_and_method_handles_from_map() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[4..6].copy_from_slice(&0x0007u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&40u32.to_le_bytes());
        bytes[16..18].copy_from_slice(&0x0008u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&44u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&56u32.to_le_bytes());
        bytes[44..46].copy_from_slice(&4u16.to_le_bytes());
        bytes[48..50].copy_from_slice(&0u16.to_le_bytes());
        bytes[56..59].copy_from_slice(&[1, 0x17, 1]);
        let methods = vec![DexMethod {
            class_descriptor: "LExample;".into(),
            name: "invoke".into(),
            descriptor: "()V".into(),
        }];
        let (calls, handles) = parse_dex_link_sections(
            &bytes,
            0,
            &["unused".into(), "value".into()],
            &[],
            &[],
            &methods,
        );
        assert_eq!(calls.len(), 1);
        assert!(
            matches!(calls[0].values[0], DexEncodedValue::String(Some(ref value)) if value == "value")
        );
        assert_eq!(handles[0].kind, "invoke_static");
        assert_eq!(handles[0].target.as_deref(), Some("LExample;->invoke()V"));
    }

    #[test]
    fn decodes_explicit_static_values_and_preserves_omitted_fields() {
        let bytes = [0, 3, 0x04, 0x2a, 0x1e, 0x3f];
        let values = parse_static_values(&bytes, 1, &[4, 7, 9, 12], &[], &[]);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0].field_index, 4);
        assert!(matches!(values[0].value, DexEncodedValue::Integer(42)));
        assert!(matches!(values[1].value, DexEncodedValue::Null));
        assert!(matches!(values[2].value, DexEncodedValue::Boolean(true)));
        assert!(!values.iter().any(|value| value.field_index == 12));
    }

    #[test]
    fn signing_block_rejects_truncated_footer() {
        assert!(matches!(
            parse_apk_signing_block(&[0u8; 32]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn signing_block_accepts_apk_without_signature_block() {
        let mut bytes = vec![0u8; 46];
        bytes[24..28].copy_from_slice(b"PK\x05\x06");
        bytes[40..44].copy_from_slice(&24u32.to_le_bytes());
        assert!(parse_apk_signing_block(&bytes).unwrap().is_empty());
    }

    #[test]
    fn resource_variants_keep_qualifiers_and_ambiguity() {
        let mut bytes = vec![0u8; 52];
        bytes[14..16].copy_from_slice(&320u16.to_le_bytes());
        bytes[24..26].copy_from_slice(&35u16.to_le_bytes());
        assert_eq!(resource_configuration(&bytes, 0, 28), "320dpi-v35");
        let mut table = ResourceTable::default();
        table.unique.insert("@0x7f010001".into(), "one".into());
        table.variants.push(ResourceVariant {
            resource_id: "@0x7f010001".into(),
            configuration: "default".into(),
            value: "one".into(),
            source_offset: 0,
            ..ResourceVariant::default()
        });
        table.variants.push(ResourceVariant {
            resource_id: "@0x7f010001".into(),
            configuration: "fr".into(),
            value: "un".into(),
            source_offset: 1,
            ..ResourceVariant::default()
        });
        table.unique.remove("@0x7f010001");
        assert!(table.unique.is_empty());
        assert_eq!(table.variants.len(), 2);
    }

    #[test]
    fn resource_package_name_preserves_bounded_utf16_identity() {
        let mut bytes = vec![0u8; 12 + 256];
        let name: Vec<u16> = "com.example".encode_utf16().collect();
        for (index, unit) in name.into_iter().enumerate() {
            bytes[12 + index * 2..14 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            resource_package_name(&bytes, 0).as_deref(),
            Some("com.example")
        );
    }

    #[test]
    fn resource_package_name_reports_invalid_utf16() {
        let mut bytes = vec![0u8; 12 + 256];
        bytes[12..14].copy_from_slice(&0xd800u16.to_le_bytes());

        let (name, issue) = resource_package_name_facts(&bytes, 0);

        assert_eq!(name, None);
        assert_eq!(
            issue.as_deref(),
            Some("resource package name contains invalid UTF-16")
        );
    }

    #[test]
    fn resource_configuration_facts_preserve_qualifiers_and_truncation() {
        let mut bytes = vec![0u8; 28];
        bytes[4..6].copy_from_slice(&310u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&260u16.to_le_bytes());
        bytes[8..10].copy_from_slice(b"en");
        bytes[10..12].copy_from_slice(b"US");
        bytes[12] = 2;
        bytes[13] = 3;
        bytes[14..16].copy_from_slice(&320u16.to_le_bytes());
        bytes[16] = 2;
        bytes[17] = 1;
        bytes[18] = 0x05;
        bytes[20..22].copy_from_slice(&1080u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&1920u16.to_le_bytes());
        bytes[24..26].copy_from_slice(&35u16.to_le_bytes());
        let facts = resource_configuration_facts(&bytes, 0, 28);
        assert_eq!(facts.locale.as_deref(), Some("en"));
        assert_eq!(facts.region.as_deref(), Some("US"));
        assert_eq!(facts.mcc, Some(310));
        assert_eq!(facts.mnc, Some(260));
        assert_eq!(facts.density, Some(320));
        assert_eq!(facts.sdk, Some(35));
        assert_eq!(facts.orientation, Some(2));
        assert_eq!(facts.touchscreen, Some(3));
        assert_eq!(facts.keyboard, Some(2));
        assert_eq!(facts.navigation, Some(1));
        assert_eq!(facts.input_flags, Some(0x05));
        assert_eq!(facts.screen_width, Some(1080));
        assert_eq!(facts.screen_height, Some(1920));
        assert!(resource_configuration_facts(&bytes, 0, 64).issue.is_some());
    }

    #[test]
    fn resource_configuration_omits_input_flags_when_the_config_is_truncated() {
        let mut bytes = vec![0u8; 18];
        bytes[16] = 2;
        bytes[17] = 1;

        let facts = resource_configuration_facts(&bytes, 0, bytes.len());

        assert_eq!(facts.keyboard, Some(2));
        assert_eq!(facts.navigation, Some(1));
        assert_eq!(facts.input_flags, None);
        assert!(facts.issue.is_none());
    }

    #[test]
    fn resource_configuration_decodes_packed_locale_and_extended_fields() {
        assert_eq!(decode_packed_locale_language(*b"en").as_deref(), Some("en"));
        assert_eq!(decode_packed_locale_region(*b"US").as_deref(), Some("US"));

        let mut bytes = vec![0u8; 44];
        bytes[8] = 0xc5;
        bytes[9] = 0x1d;
        bytes[10] = 0x90;
        bytes[11] = 0x29;
        bytes[36..40].copy_from_slice(b"Latn");
        bytes[40..44].copy_from_slice(b"POSI");
        let facts = resource_configuration_facts(&bytes, 0, bytes.len());

        assert_eq!(facts.locale.as_deref(), Some("eng"));
        assert_eq!(facts.region.as_deref(), Some("419"));
        assert_eq!(facts.locale_script.as_deref(), Some("Latn"));
        assert_eq!(facts.locale_variant.as_deref(), Some("POSI"));
        assert_eq!(facts.locale_raw, Some(bytes[8..12].to_vec()));
        assert!(resource_configuration(&bytes, 0, bytes.len()).contains("Latn"));
    }

    #[test]
    fn resource_library_mappings_keep_identity_and_truncated_ranges() {
        let mut bytes = vec![0u8; 12 + 260];
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[16..18].copy_from_slice(&(b'c' as u16).to_le_bytes());
        bytes[18..20].copy_from_slice(&(b'o' as u16).to_le_bytes());
        bytes[20..22].copy_from_slice(&(b'm' as u16).to_le_bytes());
        bytes[22..24].copy_from_slice(&(b'.' as u16).to_le_bytes());
        bytes[24..26].copy_from_slice(&(b'l' as u16).to_le_bytes());
        bytes[26..28].copy_from_slice(&(b'i' as u16).to_le_bytes());
        bytes[28..30].copy_from_slice(&(b'b' as u16).to_le_bytes());

        let mappings = parse_resource_library_chunk(&bytes, 0, bytes.len());
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].package_id, Some(0x80));
        assert_eq!(mappings[0].package_name.as_deref(), Some("com.lib"));
        assert_eq!(mappings[0].source_range, (12, 272));
        assert!(mappings[0].issue.is_none());

        let truncated = parse_resource_library_chunk(&bytes[..100], 0, 100);
        assert_eq!(truncated[0].source_range, (12, 100));
        assert_eq!(
            truncated[0].issue.as_deref(),
            Some("resource library mapping is truncated")
        );
    }

    #[test]
    fn resource_staged_aliases_keep_ids_and_exact_ranges() {
        let mut bytes = vec![0u8; 12 + 16];
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x7f010001u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x7f010101u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&0x7f020001u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&0x7f020101u32.to_le_bytes());

        let aliases = parse_resource_staged_alias_chunk(&bytes, 0, bytes.len());

        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases[0].staged_id_raw, Some(0x7f010001));
        assert_eq!(aliases[0].final_id.as_deref(), Some("0x7f010101"));
        assert_eq!(aliases[0].source_range, (12, 20));
        assert!(aliases[0].issue.is_none());
        assert_eq!(aliases[1].source_range, (20, 28));
    }

    #[test]
    fn resource_staged_aliases_preserve_truncated_record_issue() {
        let mut bytes = vec![0u8; 16];
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x7f010001u32.to_le_bytes());

        let aliases = parse_resource_staged_alias_chunk(&bytes, 0, bytes.len());

        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].source_range, (12, 16));
        assert_eq!(
            aliases[0].issue.as_deref(),
            Some("resource staged alias is truncated")
        );
        assert!(aliases[0].staged_id_raw.is_none());
    }

    #[test]
    fn resource_staged_aliases_bound_declared_count() {
        let mut bytes = vec![0u8; 12];
        bytes[8..12].copy_from_slice(&10_001u32.to_le_bytes());

        let aliases = parse_resource_staged_alias_chunk(&bytes, 0, bytes.len());

        assert_eq!(aliases.len(), 1);
        assert_eq!(
            aliases[0].issue.as_deref(),
            Some("resource staged alias count exceeds the maximum")
        );
        assert_eq!(aliases[0].source_range, (0, 12));
    }

    #[test]
    fn resource_count_uses_table_entries_when_resources_are_parsed() {
        let table = ResourceTable {
            entries: vec![ResourceEntry::default(), ResourceEntry::default()],
            ..Default::default()
        };

        assert_eq!(resource_count(Some(&table), &["res/a.xml".into()]), 2);
    }

    #[test]
    fn resource_count_falls_back_to_zip_paths_without_a_resource_table() {
        let paths = vec!["res/a.xml".into(), "res/b.xml".into()];

        assert_eq!(resource_count(None, &paths), 2);
    }

    #[test]
    fn malformed_resource_table_does_not_produce_a_resource_count() {
        let malformed = [0u8; 8];

        assert!(matches!(
            parse_resource_table(&malformed),
            Err(Error::Malformed("resources.arsc table header is invalid"))
        ));
    }

    #[test]
    fn resource_scalar_values_keep_raw_type_and_unknown_reference_state() {
        assert_eq!(decode_resource_value(0x10, 42).as_deref(), Some("42"));
        assert_eq!(
            decode_resource_value(0x10, (-42i32) as u32).as_deref(),
            Some("-42")
        );
        assert_eq!(
            decode_resource_value(0x11, 0xfeed_beef).as_deref(),
            Some("0xfeedbeef")
        );
        assert_eq!(decode_resource_value(0x12, 1).as_deref(), Some("true"));
        assert_eq!(
            decode_resource_value(0x1c, 0xff112233).as_deref(),
            Some("#0xff112233")
        );
        assert_eq!(decode_resource_value(0x01, 0x7f010001), None);
        assert_eq!(decode_resource_value(0x7f, 1), None);
    }

    #[test]
    fn projects_reference_and_attribute_ids_without_claiming_resolution() {
        assert_eq!(
            resource_reference(0x01, 0x7f010001).as_deref(),
            Some("@0x7f010001")
        );
        assert_eq!(
            resource_reference(0x02, 0x01010000).as_deref(),
            Some("?0x01010000")
        );
        assert_eq!(resource_reference(0x10, 42), None);

        let mut bytes = vec![0u8; 28];
        bytes[4..8].copy_from_slice(&0x7f010001u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x01000000u32.to_le_bytes());
        bytes[23] = 0x02;
        bytes[24..28].copy_from_slice(&0x01010000u32.to_le_bytes());
        let pool = StringPool {
            values: Vec::new(),
            utf8: false,
            entry_source_ranges: Vec::new(),
            invalid_utf16: Vec::new(),
            invalid_utf16_source_offsets: Vec::new(),
            chunk_size: 0,
            source_offset: 0,
        };
        let (_, values, issue) = parse_resource_complex_values(&bytes, 0, bytes.len(), &pool);

        assert!(issue.is_none());
        assert_eq!(values[0].decoded_value, None);
        assert_eq!(values[0].reference_id.as_deref(), Some("?0x01010000"));
    }

    #[test]
    fn projects_dynamic_resource_references_with_their_distinct_kind() {
        assert_eq!(
            resource_reference(0x07, 0x7f010001).as_deref(),
            Some("@dynamic:0x7f010001")
        );
        assert_eq!(
            resource_reference(0x08, 0x01010000).as_deref(),
            Some("?dynamic:0x01010000")
        );
        assert_eq!(resource_value_kind(0x07), "dynamic_reference");
        assert_eq!(resource_value_kind(0x08), "dynamic_attribute");
        assert_eq!(
            resource_variant_display(0x07, 0x7f010001, None),
            "@dynamic:0x7f010001"
        );
        assert_eq!(resource_value_issue(0x08, 0x01010000, None), None);
    }

    #[test]
    fn preserves_unknown_dynamic_value_types_and_raw_data() {
        assert_eq!(resource_reference(0x09, 0x7f010001), None);
        assert_eq!(resource_value_kind(0x09), "unknown");
        assert_eq!(
            resource_variant_display(0x09, 0x7f010001, None),
            "0x7f010001"
        );
        assert_eq!(
            resource_value_issue(0x09, 0x7f010001, None).as_deref(),
            Some("resource value type is unknown")
        );
    }

    #[test]
    fn typed_resource_variants_keep_numeric_and_reference_display_values() {
        assert_eq!(resource_variant_display(0x10, 42, Some("42")), "42");
        assert_eq!(
            resource_variant_display(0x11, 0xfeed_beef, Some("0xfeedbeef")),
            "0xfeedbeef"
        );
        assert_eq!(
            resource_variant_display(0x01, 0x7f010001, None),
            "@0x7f010001"
        );
        assert_eq!(resource_variant_display(0x7f, 42, None), "0x0000002a");
    }

    #[test]
    fn decodes_explicit_null_resource_values() {
        assert_eq!(decode_resource_value(0x00, 0).as_deref(), Some("null"));
        assert_eq!(decode_resource_value(0x00, 1).as_deref(), Some("undefined"));
        assert_eq!(resource_value_kind(0x00), "null");
        assert_eq!(resource_variant_display(0x00, 0, None), "null");
        assert_eq!(resource_value_issue(0x00, 1, Some("undefined")), None);
    }

    #[test]
    fn preserves_unknown_null_payload_as_an_issue() {
        assert_eq!(decode_resource_value(0x00, 2), None);
        assert_eq!(resource_variant_display(0x00, 2, None), "0x00000002");
        assert_eq!(
            resource_value_issue(0x00, 2, None).as_deref(),
            Some("resource value type is unknown")
        );
    }

    #[test]
    fn resource_variant_issues_distinguish_unknown_types_from_references() {
        assert_eq!(
            resource_value_issue(0x7f, 42, None).as_deref(),
            Some("resource value type is unknown")
        );
        assert_eq!(resource_value_issue(0x01, 0x7f010001, None), None);
        assert_eq!(resource_value_issue(0x10, 42, Some("42")), None);
    }

    #[test]
    fn decodes_dimension_and_fraction_resource_values() {
        let dimension = (16u32 << 8) | 0x01;
        assert_eq!(
            decode_resource_value(0x05, dimension).as_deref(),
            Some("16dp")
        );

        let fraction = (50u32 << 8) | 0x00;
        assert_eq!(
            decode_resource_value(0x06, fraction).as_deref(),
            Some("50%")
        );

        let negative_dimension = ((-8i32 as u32) & 0x00ff_ffff) << 8 | 0x00;
        assert_eq!(
            decode_resource_value(0x05, negative_dimension).as_deref(),
            Some("-8px")
        );
    }

    #[test]
    fn resource_complex_values_preserve_parent_keys_and_partial_unknowns() {
        let mut bytes = vec![0u8; 40];
        bytes[4..8].copy_from_slice(&0x7f010000u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        // map[0]: key=0x01000000, string-pool index 0
        bytes[16..20].copy_from_slice(&0x01000000u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&8u16.to_le_bytes());
        bytes[23] = 0x03;
        bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
        // map[1]: key=0x01000001, unknown type with raw data
        bytes[28..32].copy_from_slice(&0x01000001u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&8u16.to_le_bytes());
        bytes[35] = 0x7f;
        bytes[36..40].copy_from_slice(&42u32.to_le_bytes());
        let pool = StringPool {
            values: vec!["label".to_owned()],
            utf8: false,
            entry_source_ranges: Vec::new(),
            invalid_utf16: Vec::new(),
            invalid_utf16_source_offsets: Vec::new(),
            chunk_size: 0,
            source_offset: 0,
        };

        let (parent, values, issue) = parse_resource_complex_values(&bytes, 0, bytes.len(), &pool);

        assert_eq!(parent, Some(0x7f010000));
        assert!(issue.is_none());
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].key, 0x01000000);
        assert_eq!(values[0].key_resource_id, "@0x01000000");
        assert_eq!(values[0].value_kind, "string");
        assert_eq!(values[0].decoded_value.as_deref(), Some("label"));
        assert_eq!(values[0].value_size, Some(8));
        assert_eq!(values[0].value_res0, Some(0));
        assert_eq!(values[0].string_pool_index, Some(0));
        assert_eq!(values[0].string_pool_source_offset, Some(8));
        assert_eq!(values[0].source_offset, 16);
        assert_eq!(values[1].value_data, Some(42));
        assert_eq!(values[1].value_kind, "unknown");
        assert_eq!(
            values[1].issue.as_deref(),
            Some("resource complex value type is unknown")
        );
    }

    #[test]
    fn decodes_float_resource_values_without_losing_raw_bits() {
        let bits = 1.5f32.to_bits();
        assert_eq!(decode_resource_value(0x04, bits).as_deref(), Some("1.5"));

        let mut bytes = vec![0u8; 28];
        bytes[4..8].copy_from_slice(&0x7f010001u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x01000000u32.to_le_bytes());
        bytes[23] = 0x04;
        bytes[24..28].copy_from_slice(&bits.to_le_bytes());
        let pool = StringPool {
            values: Vec::new(),
            utf8: false,
            entry_source_ranges: Vec::new(),
            invalid_utf16: Vec::new(),
            invalid_utf16_source_offsets: Vec::new(),
            chunk_size: 0,
            source_offset: 0,
        };

        let (parent, values, issue) = parse_resource_complex_values(&bytes, 0, bytes.len(), &pool);

        assert_eq!(parent, Some(0x7f010001));
        assert!(issue.is_none());
        assert_eq!(values[0].value_type, Some(0x04));
        assert_eq!(values[0].value_data, Some(bits));
        assert_eq!(values[0].decoded_value.as_deref(), Some("1.5"));
    }

    #[test]
    fn resource_string_pool_preserves_invalid_utf16_and_duplicate_indices() {
        let mut bytes = vec![0u8; 58];
        bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&28u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&(58u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&28u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&6u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&12u32.to_le_bytes());
        bytes[40..42].copy_from_slice(&1u16.to_le_bytes());
        bytes[42..44].copy_from_slice(&0xd800u16.to_le_bytes());
        bytes[44..46].copy_from_slice(&0u16.to_le_bytes());
        bytes[46..48].copy_from_slice(&1u16.to_le_bytes());
        bytes[48..50].copy_from_slice(&0x0061u16.to_le_bytes());
        bytes[50..52].copy_from_slice(&0u16.to_le_bytes());
        bytes[52..54].copy_from_slice(&1u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&0x0061u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&0u16.to_le_bytes());

        let pool = StringPool::read(&bytes, 0).expect("fixture string pool is valid");

        assert_eq!(pool.values.len(), 3);
        assert_eq!(pool.source_offset, 0);
        assert!(!pool.utf8);
        assert_eq!(pool.entry_source_ranges, vec![(40, 44), (46, 50), (52, 56)]);
        assert_eq!(pool.invalid_utf16, vec![0]);
        assert_eq!(pool.invalid_utf16_source_offsets, vec![40]);
        assert_eq!(pool.values[0], "�");
        assert_eq!(pool.values[1], "a");
        assert_eq!(pool.values[2], "a");
        assert!(pool.get(99).is_none());
    }

    #[test]
    fn qualified_binary_xml_names_preserve_namespace_and_unknown_fallbacks() {
        let mut namespaces = vec![NamespaceBinding {
            prefix_index: 3,
            uri_index: 7,
            prefix: "android".to_owned(),
        }];

        assert_eq!(
            qualified_binary_xml_name(Some("name"), 7, &namespaces),
            "android:name"
        );
        namespaces.push(NamespaceBinding {
            prefix_index: 4,
            uri_index: 7,
            prefix: "platform".to_owned(),
        });
        assert_eq!(
            qualified_binary_xml_name(Some("name"), 7, &namespaces),
            "platform:name"
        );
        let removed = namespaces
            .iter()
            .rposition(|binding| binding.prefix_index == 4 && binding.uri_index == 7)
            .expect("rebound namespace exists");
        namespaces.remove(removed);
        assert_eq!(
            qualified_binary_xml_name(Some("name"), 7, &namespaces),
            "android:name"
        );
        assert_eq!(
            qualified_binary_xml_name(Some("name"), 11, &namespaces),
            "{unknown-namespace:11}name"
        );
        assert_eq!(
            qualified_binary_xml_name(None, u32::MAX as usize, &namespaces),
            "<unresolved-name>"
        );
    }

    #[test]
    fn binary_xml_attribute_values_preserve_typed_decoding_and_unknowns() {
        assert_eq!(
            decode_binary_xml_attribute_value(0x00, 0, None),
            "undefined"
        );
        assert_eq!(decode_binary_xml_attribute_value(0x00, 1, None), "null");
        assert_eq!(
            decode_binary_xml_attribute_value(0x00, 2, None),
            "<invalid-null:0x00000002>"
        );
        assert_eq!(
            decode_binary_xml_attribute_value(0x03, 2, Some("label")),
            "label"
        );
        assert_eq!(
            decode_binary_xml_attribute_value(0x03, 2, None),
            "<string-pool:2>"
        );
        assert_eq!(
            decode_binary_xml_attribute_value(0x01, 0x7f010001, None),
            "@0x7f010001"
        );
        assert_eq!(decode_binary_xml_attribute_value(0x12, 0, None), "false");
        assert_eq!(
            decode_binary_xml_attribute_value(0x10, (-7i32) as u32, None),
            "-7"
        );
        assert_eq!(
            decode_binary_xml_attribute_value(0x05, (8u32 << 8) | 1, None),
            "8dp"
        );
        assert_eq!(
            decode_binary_xml_attribute_value(0x7f, 42, None),
            "<unknown-type:0x7f:0x0000002a>"
        );
    }

    #[test]
    fn resource_name_mapping_preserves_pool_indices_and_unresolved_keys() {
        let type_pool = StringPool {
            values: vec!["string".into()],
            utf8: false,
            entry_source_ranges: Vec::new(),
            invalid_utf16: Vec::new(),
            invalid_utf16_source_offsets: Vec::new(),
            chunk_size: 32,
            source_offset: 0,
        };
        let key_pool = StringPool {
            values: vec!["title".into(), "title".into()],
            utf8: false,
            entry_source_ranges: Vec::new(),
            invalid_utf16: vec![1],
            invalid_utf16_source_offsets: vec![0],
            chunk_size: 40,
            source_offset: 0,
        };
        let mapping = ResourcePoolMapping {
            package_id: 0x7f,
            package_name: Some("com.example"),
            package_name_source_offset: 100,
            type_pool: Some(&type_pool),
            type_pool_source_offset: Some(200),
            type_pool_issue: None,
            key_pool: Some(&key_pool),
            key_pool_source_offset: Some(300),
            key_pool_issue: None,
        };

        let resolved = resource_name_facts(&mapping, 1, Some(0));
        assert_eq!(resolved.package_id, 0x7f);
        assert_eq!(resolved.package_name.as_deref(), Some("com.example"));
        assert_eq!(resolved.type_name.as_deref(), Some("string"));
        assert_eq!(resolved.type_name_index, Some(0));
        assert_eq!(resolved.key_name.as_deref(), Some("title"));
        assert_eq!(
            resolved.qualified_name.as_deref(),
            Some("com.example:string/title")
        );
        assert_eq!(resolved.key_name_index, Some(0));
        assert_eq!(resolved.type_pool_source_offset, Some(200));
        assert_eq!(resolved.key_pool_source_offset, Some(300));
        assert!(resolved.mapping_issue.is_none());

        let invalid_duplicate = resource_name_facts(&mapping, 1, Some(1));
        assert_eq!(invalid_duplicate.key_name.as_deref(), Some("title"));
        assert_eq!(invalid_duplicate.key_name_index, Some(1));
        assert_eq!(
            invalid_duplicate.mapping_issue.as_deref(),
            Some("resource key pool entry contains invalid UTF-16")
        );

        let missing = resource_name_facts(&mapping, 2, Some(99));
        assert_eq!(missing.type_name, None);
        assert_eq!(missing.type_name_index, Some(1));
        assert_eq!(missing.key_name, None);
        assert_eq!(missing.key_name_index, Some(99));
        assert_eq!(
            missing.mapping_issue.as_deref(),
            Some(
                "resource type pool index 1 is unresolved; resource key pool index 99 is unresolved"
            )
        );
    }

    #[test]
    fn android_class_name_projection_preserves_order_repeats_and_partial_rows() {
        let dex = DexFacts {
            entry: "classes.dex".into(),
            classes: vec!["LExample;".into(), "LExample;".into(), String::new()],
            class_definitions: vec![
                DexClass {
                    descriptor: "LExample;".into(),
                    source_offset: 0x70,
                    superclass: None,
                    interfaces: Vec::new(),
                    fields: Vec::new(),
                    methods: Vec::new(),
                    static_values: Vec::new(),
                },
                DexClass {
                    descriptor: "LExample;".into(),
                    source_offset: 0x90,
                    superclass: None,
                    interfaces: Vec::new(),
                    fields: Vec::new(),
                    methods: Vec::new(),
                    static_values: Vec::new(),
                },
            ],
            truncated: true,
            ..DexFacts::default()
        };

        let (rows, coverage) = android_class_name_projection(&[dex], 4);

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].name.as_deref(), Some("LExample;"));
        assert_eq!(rows[1].name.as_deref(), Some("LExample;"));
        assert_eq!(rows[0].dex_index, 0);
        assert_eq!(rows[1].dex_index, 1);
        assert_eq!(rows[0].source_offset, Some(0x70));
        assert_eq!(rows[1].source_offset, Some(0x90));
        assert_eq!(rows[2].name, None);
        assert_eq!(rows[2].status, "unknown");
        assert_eq!(coverage.status, "partial");
        assert_eq!(coverage.reported_total, 4);
        assert_eq!(coverage.observed_rows, 3);
        assert_eq!(coverage.unknown_rows, 1);
    }

    #[test]
    fn resource_configuration_keeps_modern_screen_qualifiers() {
        let mut bytes = vec![0u8; 36];
        bytes[28] = 0x23;
        bytes[29] = 0x11;
        bytes[30..32].copy_from_slice(&600u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&800u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&1280u16.to_le_bytes());

        let facts = resource_configuration_facts(&bytes, 0, bytes.len());

        assert_eq!(facts.screen_layout, Some(0x23));
        assert_eq!(facts.ui_mode, Some(0x11));
        assert_eq!(facts.smallest_width, Some(600));
        assert_eq!(facts.screen_width_dp, Some(800));
        assert_eq!(facts.screen_height_dp, Some(1280));
        assert!(facts.issue.is_none());
    }

    #[test]
    fn resource_configuration_formats_screen_and_ui_qualifiers() {
        let mut bytes = vec![0u8; 36];
        bytes[28] = 0x03;
        bytes[29] = 0x23;
        bytes[30..32].copy_from_slice(&600u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&800u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&1280u16.to_le_bytes());

        assert_eq!(
            resource_configuration(&bytes, 0, bytes.len()),
            "large-car-night-sw600dp-w800dp-h1280dp"
        );
    }

    #[test]
    fn resource_configuration_formats_device_qualifiers() {
        let mut bytes = vec![0u8; 18];
        bytes[12] = 2;
        bytes[13] = 3;
        bytes[16] = 2;
        bytes[17] = 4;

        assert_eq!(
            resource_configuration(&bytes, 0, bytes.len()),
            "land-finger-qwerty-wheel"
        );
    }

    #[test]
    fn resource_configuration_ignores_unknown_device_qualifiers() {
        let mut bytes = vec![0u8; 18];
        bytes[12] = 0xff;
        bytes[13] = 0xff;
        bytes[16] = 0xff;
        bytes[17] = 0xff;

        assert_eq!(resource_configuration(&bytes, 0, bytes.len()), "default");
    }

    #[test]
    fn resource_configuration_decodes_screen_layout_and_color_mode() {
        let mut bytes = vec![0u8; 46];
        bytes[44] = 0x02;
        bytes[45] = 0x0a;

        let facts = resource_configuration_facts(&bytes, 0, bytes.len());

        assert_eq!(facts.screen_layout_2, Some(0x02));
        assert_eq!(facts.color_mode, Some(0x0a));
        assert_eq!(
            resource_configuration(&bytes, 0, bytes.len()),
            "round-widecg-highdr"
        );
    }

    #[test]
    fn resource_configuration_omits_screen_config2_when_truncated() {
        let bytes = vec![0u8; 45];

        let facts = resource_configuration_facts(&bytes, 0, bytes.len());

        assert_eq!(facts.screen_layout_2, None);
        assert_eq!(facts.color_mode, None);
        assert!(facts.issue.is_none());
    }

    #[test]
    fn resource_configuration_preserves_sdk_minor_version() {
        let mut bytes = vec![0u8; 28];
        bytes[24..26].copy_from_slice(&35u16.to_le_bytes());
        bytes[26..28].copy_from_slice(&2u16.to_le_bytes());

        let facts = resource_configuration_facts(&bytes, 0, bytes.len());

        assert_eq!(facts.sdk, Some(35));
        assert_eq!(facts.sdk_minor, Some(2));
        assert!(facts.issue.is_none());
    }

    #[test]
    fn resource_configuration_omits_sdk_minor_version_when_truncated() {
        let mut bytes = vec![0u8; 27];
        bytes[24..26].copy_from_slice(&35u16.to_le_bytes());

        let facts = resource_configuration_facts(&bytes, 0, bytes.len());

        assert_eq!(facts.sdk, None);
        assert_eq!(facts.sdk_minor, None);
        assert!(facts.issue.is_none());
    }

    #[test]
    fn sparse_resource_entries_keep_their_derived_identity() {
        let mut bytes = vec![0u8; 32];
        bytes[8] = 1;
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&32u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&4u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        let mapping = ResourcePoolMapping {
            package_id: 0x7f,
            package_name: None,
            package_name_source_offset: 0,
            type_pool: None,
            type_pool_source_offset: None,
            type_pool_issue: None,
            key_pool: None,
            key_pool_source_offset: None,
            key_pool_issue: None,
        };
        let global_pool = empty_string_pool();
        let mut values = ResourceTable::default();

        parse_resource_type_chunk(&bytes, 0, bytes.len(), &mapping, &global_pool, &mut values)
            .expect("sparse entry should be retained");

        assert_eq!(values.entries[0].resource_id, "@0x7f010000");
        assert_eq!(
            values.entries[0].issue.as_deref(),
            Some("sparse resource entry")
        );
    }

    #[test]
    fn resource_entries_preserve_header_flags() {
        let mut bytes = vec![0u8; 48];
        bytes[8] = 1;
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&32u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&4u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&8u16.to_le_bytes());
        bytes[36..40].copy_from_slice(&0u32.to_le_bytes());
        bytes[40..42].copy_from_slice(&8u16.to_le_bytes());
        bytes[43] = 0x10;
        bytes[44..48].copy_from_slice(&7u32.to_le_bytes());
        let mapping = ResourcePoolMapping {
            package_id: 0x7f,
            package_name: None,
            package_name_source_offset: 0,
            type_pool: None,
            type_pool_source_offset: None,
            type_pool_issue: None,
            key_pool: None,
            key_pool_source_offset: None,
            key_pool_issue: None,
        };
        let mut values = ResourceTable::default();

        parse_resource_type_chunk(
            &bytes,
            0,
            bytes.len(),
            &mapping,
            &empty_string_pool(),
            &mut values,
        )
        .expect("entry should parse");

        assert_eq!(values.entries[0].flags, Some(0));
        assert_eq!(values.entries[0].entry_size, Some(8));
        assert_eq!(values.entries[0].value_size, Some(8));
        assert_eq!(values.entries[0].value_res0, Some(0));
    }

    #[test]
    fn apk_resource_paths_retain_files_and_skip_directories() {
        let entries = vec![
            Entry {
                name: "res/layout/main.xml",
                method: 0,
                compressed: &[],
                size: 0,
            },
            Entry {
                name: "res/layout/",
                method: 0,
                compressed: &[],
                size: 0,
            },
            Entry {
                name: "classes.dex",
                method: 0,
                compressed: &[],
                size: 0,
            },
        ];

        assert_eq!(apk_resource_paths(&entries), vec!["res/layout/main.xml"]);
    }

    #[test]
    fn resource_pool_keeps_its_package_name_context() {
        let pool = ResourcePool {
            package_id: 0x7f,
            package_name: Some("com.example".into()),
            kind: "key".into(),
            ..ResourcePool::default()
        };

        assert_eq!(pool.package_id, 0x7f);
        assert_eq!(pool.package_name.as_deref(), Some("com.example"));
        assert_eq!(pool.kind, "key");
    }
}
