//! Bounded PE/CLI metadata inspection for managed artifacts.
//!
//! This reader deliberately keeps the first migration slice small: it admits
//! the PE CLI header, metadata root streams, Module/Assembly/AssemblyRef rows,
//! and stable identities. Unsupported tables remain explicit in `limitations`.

use serde::Serialize;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;

pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_EMBEDDED_RESOURCE_BYTES: usize = 1024 * 1024;
const MAX_FIELD_DATA_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    Unsupported(&'static str),
    ResourceLimit(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(reason) | Self::Unsupported(reason) => f.write_str(reason),
            Self::ResourceLimit(reason) => f.write_str(reason),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub artifact: Artifact,
    pub pe: Pe,
    pub debug: Option<CodeView>,
    pub classification: Classification,
    pub metadata: Metadata,
    pub module: Option<Module>,
    pub assembly: Option<Assembly>,
    pub assembly_processors: Vec<AssemblyProcessor>,
    pub assembly_os: Vec<AssemblyOs>,
    pub assembly_ref_processors: Vec<AssemblyRefProcessor>,
    pub assembly_ref_os: Vec<AssemblyRefOs>,
    pub files: Vec<ManagedFile>,
    pub references: Vec<AssemblyReference>,
    pub module_references: Vec<ModuleReference>,
    pub impl_maps: Vec<ImplMap>,
    pub type_references: Vec<TypeReference>,
    pub types: Vec<TypeDefinition>,
    pub fields: Vec<FieldDefinition>,
    pub field_rvas: Vec<FieldRva>,
    pub field_layouts: Vec<FieldLayout>,
    pub field_marshals: Vec<FieldMarshal>,
    pub decl_security: Vec<DeclSecurity>,
    pub class_layouts: Vec<ClassLayout>,
    pub methods: Vec<MethodDefinition>,
    pub member_references: Vec<MemberReference>,
    pub params: Vec<ParameterDefinition>,
    pub generic_params: Vec<GenericParameter>,
    pub generic_constraints: Vec<GenericParameterConstraint>,
    pub type_specs: Vec<TypeSpecification>,
    pub method_specs: Vec<MethodSpecification>,
    pub standalone_signatures: Vec<StandaloneSignature>,
    pub property_maps: Vec<PropertyMap>,
    pub properties: Vec<PropertyDefinition>,
    pub method_semantics: Vec<MethodSemantic>,
    pub event_maps: Vec<EventMap>,
    pub events: Vec<EventDefinition>,
    pub interface_impls: Vec<InterfaceImplementation>,
    pub method_impls: Vec<MethodImplementation>,
    pub custom_attributes: Vec<CustomAttribute>,
    pub constants: Vec<Constant>,
    pub manifest_resources: Vec<ManifestResource>,
    pub exported_types: Vec<ExportedType>,
    pub target_frameworks: Vec<String>,
    pub nested_classes: Vec<NestedClass>,
    pub coverage: Coverage,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ManagedMembersSelection {
    pub type_names: Option<Vec<String>>,
    pub unmatched_type_names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ManagedMembersInspection<'a> {
    pub module: Option<&'a Module>,
    pub assembly: Option<&'a Assembly>,
    pub references: &'a [AssemblyReference],
    pub module_references: &'a [ModuleReference],
    pub exported_types: &'a [ExportedType],
    pub types: Vec<&'a TypeDefinition>,
    pub fields: Vec<&'a FieldDefinition>,
    pub methods: Vec<&'a MethodDefinition>,
    pub params: Vec<&'a ParameterDefinition>,
    pub properties: Vec<&'a PropertyDefinition>,
    pub events: Vec<&'a EventDefinition>,
    pub generic_params: Vec<&'a GenericParameter>,
    pub generic_constraints: Vec<&'a GenericParameterConstraint>,
    pub method_specs: Vec<&'a MethodSpecification>,
    pub member_references: &'a [MemberReference],
    pub call_edges: Vec<CallEdge>,
    pub field_accesses: Vec<FieldAccess>,
    pub selection: ManagedMembersSelection,
}

#[derive(Debug, Serialize)]
pub struct Artifact {
    pub byte_length: usize,
    pub format: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Pe {
    pub machine: u16,
    pub machine_hex: String,
    pub architecture: &'static str,
    pub section_count: u16,
    pub characteristics: u16,
    pub cli: Option<Cli>,
}
#[derive(Debug, Serialize)]
pub struct CodeView {
    pub format: &'static str,
    pub pdb_path: String,
    pub pdb_file_name: String,
    pub guid: Option<String>,
    pub age: u32,
    pub data_offset: usize,
}
#[derive(Debug, Serialize)]
pub struct Cli {
    pub header_offset: usize,
    pub header_size: u32,
    pub runtime_version: String,
    pub flags: u32,
    pub flag_names: Vec<&'static str>,
    pub entry_point: Option<String>,
    pub metadata_rva: u32,
    pub metadata_size: u32,
}
#[derive(Debug, Serialize)]
pub struct Classification {
    pub status: &'static str,
    pub runtime_family: &'static str,
    pub implementation: &'static str,
    pub managed_architecture: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Metadata {
    pub status: &'static str,
    pub version: Option<String>,
    pub stream_names: Vec<String>,
    pub table_row_counts: std::collections::BTreeMap<String, u32>,
}
#[derive(Debug, Serialize)]
pub struct Module {
    /// File offset of the Module row in the metadata tables stream.
    ///
    /// This is retained separately from the build-local token so callers can
    /// locate the exact source row even when a malformed heap index prevents
    /// a stable identity from being derived.
    pub row_offset: Option<usize>,
    pub name: String,
    pub generation: u16,
    pub mvid: Option<String>,
    pub enc_id: Option<String>,
    pub enc_base_id: Option<String>,
    pub token: String,
}
#[derive(Debug, Serialize)]
pub struct Assembly {
    /// File offset of the Assembly row in the metadata tables stream.
    pub row_offset: Option<usize>,
    pub name: String,
    pub version: String,
    pub culture: Option<String>,
    pub flags: u32,
    pub hash_algorithm: u32,
    pub public_key_offset: Option<usize>,
    pub public_key_kind: &'static str,
    pub public_key_byte_length: usize,
    pub public_key_sha256: Option<String>,
    pub public_key_token: Option<String>,
    pub token: String,
    pub custom_attributes: Vec<CustomAttribute>,
}
#[derive(Debug, Serialize)]
pub struct AssemblyReference {
    pub name: String,
    pub version: String,
    pub culture: Option<String>,
    pub flags: u32,
    pub token: String,
    pub public_key_or_token_offset: Option<usize>,
    pub public_key_or_token_hex: Option<String>,
    pub hash_value_offset: Option<usize>,
    pub hash_value_hex: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ModuleReference {
    pub source_offset: Option<usize>,
    pub name: String,
    pub token: String,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ImplMap {
    pub token: String,
    pub source_offset: Option<usize>,
    pub flags: Option<u16>,
    pub flag_names: Vec<&'static str>,
    pub unknown_flags: u16,
    pub raw_member_forwarded: Option<usize>,
    pub member_token: Option<String>,
    pub import_name: String,
    pub module_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct TypeReference {
    pub token: String,
    pub source_offset: Option<usize>,
    pub name: String,
    pub namespace: String,
    pub raw_resolution_scope: Option<usize>,
    pub resolution_scope_kind: Option<&'static str>,
    pub resolution_scope_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct TypeDefinition {
    pub token: String,
    pub row_offset: Option<usize>,
    pub name: String,
    pub namespace: String,
    pub full_name: String,
    pub name_sha256: Option<String>,
    pub flags: u32,
    pub extends_token: Option<String>,
    pub field_list: MemberList,
    pub method_list: MemberList,
    pub custom_attributes: Vec<CustomAttribute>,
    pub interface_impl_tokens: Vec<String>,
    pub method_impl_tokens: Vec<String>,
    pub enclosing_type_token: Option<String>,
    pub nested_type_tokens: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct MemberList {
    pub first_row: Option<u32>,
    pub last_row: Option<u32>,
    pub count: u32,
}
#[derive(Debug, Serialize)]
pub struct FieldDefinition {
    pub token: String,
    pub source_offset: Option<usize>,
    pub declaring_type_token: Option<String>,
    pub declaring_type: Option<String>,
    pub name: String,
    pub flags: u16,
    pub signature: Signature,
    pub constants: Vec<Constant>,
    pub rva: Option<u32>,
    pub data_offset: Option<usize>,
    pub data_hex: Option<String>,
    pub layout_offset: Option<u32>,
    pub custom_attributes: Vec<CustomAttribute>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct FieldRva {
    pub token: String,
    pub source_offset: Option<usize>,
    pub field_token: Option<String>,
    pub rva: Option<u32>,
    pub data_offset: Option<usize>,
    pub data_hex: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct FieldLayout {
    pub token: String,
    pub source_offset: Option<usize>,
    pub field_token: Option<String>,
    pub offset: Option<u32>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct FieldMarshal {
    pub token: String,
    pub source_offset: Option<usize>,
    pub parent_token: Option<String>,
    pub native_type_blob_offset: usize,
    pub native_type_blob_hex: Option<String>,
    pub decoded_native_type: Option<&'static str>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct DeclSecurity {
    pub token: String,
    pub source_offset: Option<usize>,
    pub action: Option<u16>,
    pub parent_token: Option<String>,
    pub permission_blob_offset: usize,
    pub permission_blob_hex: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ClassLayout {
    pub token: String,
    pub source_offset: Option<usize>,
    pub packing_size: Option<u16>,
    pub class_size: Option<u32>,
    pub parent_type_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct AssemblyProcessor {
    pub token: String,
    pub source_offset: Option<usize>,
    pub processor: Option<u32>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct AssemblyOs {
    pub token: String,
    pub source_offset: Option<usize>,
    pub platform_id: Option<u32>,
    pub major_version: Option<u32>,
    pub minor_version: Option<u32>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct AssemblyRefProcessor {
    pub token: String,
    pub source_offset: Option<usize>,
    pub processor: Option<u32>,
    pub assembly_ref_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct AssemblyRefOs {
    pub token: String,
    pub source_offset: Option<usize>,
    pub platform_id: Option<u32>,
    pub major_version: Option<u32>,
    pub minor_version: Option<u32>,
    pub assembly_ref_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ManagedFile {
    pub token: String,
    pub source_offset: Option<usize>,
    pub flags: Option<u32>,
    pub contains_metadata: Option<bool>,
    pub name_offset: Option<usize>,
    pub name: Option<String>,
    pub hash_blob_offset: Option<usize>,
    pub hash_blob_hex: Option<String>,
    pub hash_blob_sha256: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct MethodDefinition {
    pub token: String,
    pub source_offset: Option<usize>,
    pub declaring_type_token: Option<String>,
    pub declaring_type: Option<String>,
    pub name: String,
    pub rva: u32,
    pub impl_flags: u16,
    pub impl_code_type: &'static str,
    pub impl_managed_status: &'static str,
    pub impl_flag_names: Vec<&'static str>,
    pub impl_unknown_flags: u16,
    pub flags: u16,
    pub signature: Signature,
    pub body: MethodBody,
    pub param_list: u32,
    pub custom_attributes: Vec<CustomAttribute>,
    pub impl_map_token: Option<String>,
    pub pinvoke_module_token: Option<String>,
    pub pinvoke_import_name: Option<String>,
    pub pinvoke_flags: Option<u16>,
}
#[derive(Debug, Serialize)]
pub struct MethodBody {
    pub status: &'static str,
    pub header_format: &'static str,
    pub rva: u32,
    pub file_offset: Option<usize>,
    pub max_stack: Option<u16>,
    pub init_locals: Option<bool>,
    pub il_size: usize,
    pub il_sha256: Option<String>,
    pub normalized_il_sha256: Option<String>,
    pub instruction_count: usize,
    pub decoded_instruction_count: usize,
    pub truncated_instructions: usize,
    pub opcode_counts: std::collections::BTreeMap<String, usize>,
    pub anchors: Vec<InstructionAnchor>,
    pub issue: Option<String>,
    pub exception_regions: Vec<ExceptionRegion>,
    pub local_signature_token: Option<String>,
    pub local_signature: Option<Signature>,
    pub local_signature_source_range: Option<[usize; 2]>,
}
#[derive(Debug, Serialize)]
pub struct ExceptionRegion {
    pub flags: u32,
    pub try_offset: usize,
    pub try_length: usize,
    pub handler_offset: usize,
    pub handler_length: usize,
    pub class_token: Option<String>,
    pub filter_offset: Option<usize>,
}
#[derive(Debug, Serialize)]
pub struct InstructionAnchor {
    pub il_offset: usize,
    pub opcode: String,
    pub operand_kind: &'static str,
    pub operand: Option<String>,
    pub user_string: Option<String>,
    pub user_string_offset: Option<usize>,
    pub user_string_issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct CallEdge {
    pub caller_token: String,
    pub caller: Option<String>,
    pub opcode: String,
    pub target_token: String,
    pub target_kind: &'static str,
    pub target_name: Option<String>,
    pub target_declaring_type: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct FieldAccess {
    pub method_token: String,
    pub method: Option<String>,
    pub opcode: String,
    pub field_token: String,
    pub field_name: Option<String>,
    pub field_declaring_type: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct MemberReference {
    pub token: String,
    pub row_offset: Option<usize>,
    pub name: String,
    pub parent_token: Option<String>,
    pub parent_name: Option<String>,
    pub signature: Signature,
}
#[derive(Debug, Serialize)]
pub struct ParameterDefinition {
    pub token: String,
    pub source_offset: Option<usize>,
    pub flags: u16,
    pub sequence: u16,
    pub name: String,
    pub constants: Vec<Constant>,
    pub method_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct GenericParameter {
    pub token: String,
    pub source_offset: Option<usize>,
    pub number: u16,
    pub flags: u16,
    pub owner_token: String,
    pub name: String,
    pub variance: Option<&'static str>,
    pub special_constraints: Vec<&'static str>,
    pub unknown_flags: u16,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct GenericParameterConstraint {
    pub token: String,
    pub source_offset: Option<usize>,
    pub owner_token: String,
    pub constraint_token: String,
    pub constraint_kind: &'static str,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct TypeSpecification {
    pub token: String,
    pub signature: Signature,
}
#[derive(Debug, Serialize)]
pub struct MethodSpecification {
    pub token: String,
    pub source_offset: Option<usize>,
    pub method_token: String,
    pub instantiation: Signature,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct PropertyMap {
    pub token: String,
    pub source_offset: Option<usize>,
    pub parent_type_token: String,
    pub property_list: u32,
}
#[derive(Debug, Serialize)]
pub struct PropertyDefinition {
    pub token: String,
    pub source_offset: Option<usize>,
    pub declaring_type_token: Option<String>,
    pub getter_method_token: Option<String>,
    pub setter_method_token: Option<String>,
    pub other_method_tokens: Vec<String>,
    pub flags: u16,
    pub name: String,
    pub signature: Signature,
    pub custom_attributes: Vec<CustomAttribute>,
    pub constants: Vec<Constant>,
}
#[derive(Debug, Serialize)]
pub struct MethodSemantic {
    pub token: String,
    pub source_offset: Option<usize>,
    pub semantics: u16,
    pub flag_names: Vec<&'static str>,
    pub unknown_flags: u16,
    pub method_token: String,
    pub association_token: String,
    pub association_kind: &'static str,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct EventMap {
    pub token: String,
    pub source_offset: Option<usize>,
    pub parent_type_token: String,
    pub event_list: u32,
}
#[derive(Debug, Serialize)]
pub struct EventDefinition {
    pub token: String,
    pub source_offset: Option<usize>,
    pub declaring_type_token: Option<String>,
    pub add_method_token: Option<String>,
    pub remove_method_token: Option<String>,
    pub raise_method_token: Option<String>,
    pub other_method_tokens: Vec<String>,
    pub flags: u16,
    pub name: String,
    pub event_type_token: String,
    pub custom_attributes: Vec<CustomAttribute>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CustomAttribute {
    pub token: String,
    pub source_offset: Option<usize>,
    pub parent_token: Option<String>,
    pub constructor_token: Option<String>,
    pub blob_offset: usize,
    pub blob_hex: Option<String>,
    pub value_length: usize,
    pub value_sha256: String,
    pub decoded_fixed_string: Option<String>,
    pub serialized_prolog: Option<u16>,
    pub serialized_named_argument_count: Option<u16>,
    pub serialized_shape_issue: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ManifestResource {
    pub token: String,
    pub row_source_offset: Option<usize>,
    pub name: String,
    pub flags: u32,
    pub visibility: &'static str,
    pub embedded: bool,
    pub implementation_kind: &'static str,
    pub implementation_token: Option<String>,
    pub manifest_offset: u32,
    pub source_offset: Option<usize>,
    pub size: Option<usize>,
    pub bytes_hex: Option<String>,
    pub data_sha256: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ExportedType {
    pub token: String,
    pub row_offset: Option<usize>,
    pub namespace: String,
    pub name: String,
    pub flags: u32,
    pub forwarder: bool,
    pub type_def_id: u32,
    pub implementation_kind: &'static str,
    pub implementation_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct NestedClass {
    pub token: String,
    pub source_offset: Option<usize>,
    pub nested_type_token: Option<String>,
    pub enclosing_type_token: Option<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct InterfaceImplementation {
    pub token: String,
    pub source_offset: Option<usize>,
    pub declaring_type_token: Option<String>,
    pub interface_token: Option<String>,
    pub raw_interface_index: Option<usize>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct MethodImplementation {
    pub token: String,
    pub source_offset: Option<usize>,
    pub declaring_type_token: Option<String>,
    pub body_method_token: Option<String>,
    pub declaration_method_token: Option<String>,
    pub raw_body_index: Option<usize>,
    pub raw_declaration_index: Option<usize>,
    pub issue: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Signature {
    pub raw_length: usize,
    pub raw_sha256: String,
    pub resolved_sha256: Option<String>,
    pub parse_status: &'static str,
    pub calling_convention: Option<String>,
    pub generic_parameter_count: Option<usize>,
    pub parameter_count: Option<usize>,
    pub return_type: Option<String>,
    pub parameter_types: Vec<String>,
    pub field_type: Option<String>,
    pub local_types: Vec<String>,
    pub issue: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Coverage {
    pub state: &'static str,
    pub issues: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct StandaloneSignature {
    pub token: String,
    pub source_offset: Option<usize>,
    pub signature: Signature,
    pub issue: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Constant {
    pub token: String,
    pub parent_token: Option<String>,
    pub element_type: u8,
    pub source_offset: Option<usize>,
    pub value_offset: Option<usize>,
    pub value_hex: Option<String>,
    pub decoded_value: Option<String>,
    pub issue: Option<String>,
}

pub fn inspect(bytes: &[u8]) -> Result<Inspection, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::ResourceLimit(
            "managed artifact exceeds the 256 MiB input budget",
        ));
    }
    let pe = PeLayout::read(bytes)?;
    let cli_at = pe.map(bytes, pe.cli_rva, 24)?;
    let cb = u32(bytes, cli_at)?;
    let metadata_rva = u32(bytes, cli_at + 8)?;
    let metadata_size = u32(bytes, cli_at + 12)?;
    let resources_rva = u32(bytes, cli_at + 24)?;
    let resources_size = u32(bytes, cli_at + 28)?;
    let flags = u32(bytes, cli_at + 16)?;
    let entry = u32(bytes, cli_at + 20)?;
    let metadata_at = pe.map(bytes, metadata_rva, metadata_size as usize)?;
    if metadata_size as usize > MAX_METADATA_BYTES {
        return Err(Error::ResourceLimit(
            "CLI metadata exceeds the 16 MiB decoding budget",
        ));
    }
    let root = MetadataRoot::read(&bytes[metadata_at..metadata_at + metadata_size as usize])?;
    let resource_at = (resources_rva != 0 && resources_size != 0)
        .then(|| pe.map(bytes, resources_rva, resources_size as usize).ok())
        .flatten();
    let resource_bytes = resource_at
        .and_then(|offset| bytes.get(offset..offset.saturating_add(resources_size as usize)));
    let module = root.module(bytes, &pe);
    let mut assembly = root.assembly(bytes, &pe);
    let assembly_processors = root.assembly_processors(bytes);
    let assembly_os = root.assembly_os(bytes);
    let assembly_ref_processors = root.assembly_ref_processors(bytes);
    let assembly_ref_os = root.assembly_ref_os(bytes);
    let files = root.files(bytes);
    let references = root.references(bytes, &pe);
    let module_references = root.module_references(bytes);
    let impl_maps = root.impl_maps(bytes);
    let type_references = root.type_references(bytes);
    let mut types = root.types(bytes);
    let mut fields = root.fields(bytes);
    let mut field_rvas = root.field_rvas(bytes);
    project_field_rva_data(&mut field_rvas, &pe, bytes);
    project_field_rvas(&mut fields, &field_rvas);
    let field_layouts = root.field_layouts(bytes);
    project_field_layouts(&mut fields, &field_layouts);
    let field_marshals = root.field_marshals(bytes);
    let decl_security = root.decl_security(bytes);
    let class_layouts = root.class_layouts(bytes);
    let mut methods = root.methods(bytes, &pe);
    project_member_list_ranges(&mut types, fields.len(), methods.len());
    project_member_ownership(&types, &mut fields, &mut methods);
    project_impl_maps(&mut methods, &impl_maps);
    project_user_strings(&mut methods, &root.user_strings);
    let mut member_references = root.member_references(bytes);
    let mut params = root.params(bytes);
    project_parameter_ownership(&methods, &mut params);
    let generic_params = root.generic_params(bytes);
    let generic_constraints = root.generic_constraints(bytes);
    let type_specs = root.type_specs(bytes);
    project_member_reference_parents(
        &mut member_references,
        &types,
        &type_references,
        &type_specs,
    );
    let method_specs = root.method_specs(bytes);
    let standalone_signatures = root.standalone_signatures(bytes);
    let property_maps = root.property_maps(bytes);
    let mut properties = root.properties(bytes);
    let constants = root.constants(bytes);
    project_constants(&constants, &mut fields, &mut params, &mut properties);
    project_local_signatures(&mut methods, &standalone_signatures);
    let method_semantics = root.method_semantics(bytes);
    let event_maps = root.event_maps(bytes);
    let mut events = root.events(bytes);
    let custom_attributes = root.custom_attributes(bytes);
    let custom_attributes = attach_custom_attributes(
        custom_attributes,
        &mut assembly,
        &mut types,
        &mut methods,
        &mut fields,
        &mut properties,
        &mut events,
    );
    let target_frameworks = target_frameworks(&custom_attributes, &member_references);
    let manifest_resources = root.manifest_resources(bytes, resource_bytes, resource_at);
    let exported_types = root.exported_types(bytes);
    let interface_impls = root.interface_impls(bytes);
    let method_impls = root.method_impls(bytes);
    project_type_relationships(&mut types, &interface_impls, &method_impls);
    let nested_classes = root.nested_classes(bytes);
    project_nested_classes(&mut types, &nested_classes);
    project_type_full_names(&mut types);
    project_type_name_digests(&mut types);
    project_accessor_ownership(
        &property_maps,
        &mut properties,
        &method_semantics,
        &event_maps,
        &mut events,
    );
    let debug = code_view(bytes, &pe);
    let architecture = match pe.machine {
        0x14c => "x86",
        0x8664 => "x86_64",
        0x1c0 | 0x1c4 => "arm",
        0xaa64 => "arm64",
        _ => "unknown",
    };
    let runtime_family = runtime_family(&target_frameworks, &references, flags);
    let implementation = if flags & 1 == 0 {
        "cpp-cli-mixed"
    } else if methods.is_empty() {
        "metadata-only"
    } else {
        "cil"
    };
    let mut flags_names = Vec::new();
    for (mask, name) in [
        (1, "il-only"),
        (2, "32-bit-required"),
        (4, "il-library"),
        (8, "strong-name-signed"),
        (16, "native-entry-point"),
        (0x10000, "track-debug-data"),
        (0x20000, "32-bit-preferred"),
    ] {
        if flags & mask != 0 {
            flags_names.push(name);
        }
    }
    let cli = Cli {
        header_offset: cli_at,
        header_size: cb,
        runtime_version: format!("{}.{}", u16(bytes, cli_at + 4)?, u16(bytes, cli_at + 6)?),
        flags,
        flag_names: flags_names,
        entry_point: (entry != 0).then(|| format!("0x{entry:08x}")),
        metadata_rva,
        metadata_size,
    };
    let mut limitations = vec!["TypeDef, Field, MethodDef, and MemberRef rows retain metadata identities and raw signatures. Signature grammar, CIL bodies, attributes, resources, and native boundaries remain unavailable.".to_owned()];
    if root.tables.is_none() {
        limitations.push(
            "The CLI metadata root did not contain a supported #~ or #- table stream.".to_owned(),
        );
    }
    Ok(Inspection {
        artifact: Artifact {
            byte_length: bytes.len(),
            format: "pe",
        },
        pe: Pe {
            machine: pe.machine,
            machine_hex: format!("0x{:04x}", pe.machine),
            architecture,
            section_count: pe.sections.len() as u16,
            characteristics: pe.characteristics,
            cli: Some(cli),
        },
        debug,
        classification: Classification {
            status: "managed",
            runtime_family,
            implementation,
            managed_architecture: architecture,
        },
        metadata: Metadata {
            status: "present",
            version: Some(root.version),
            stream_names: root.stream_names,
            table_row_counts: root.row_counts,
        },
        module,
        assembly,
        assembly_processors,
        assembly_os,
        assembly_ref_processors,
        assembly_ref_os,
        files,
        references,
        module_references,
        impl_maps,
        type_references,
        types,
        fields,
        field_rvas,
        field_layouts,
        field_marshals,
        decl_security,
        class_layouts,
        methods,
        member_references,
        params,
        generic_params,
        generic_constraints,
        type_specs,
        method_specs,
        standalone_signatures,
        constants,
        property_maps,
        properties,
        method_semantics,
        event_maps,
        events,
        interface_impls,
        method_impls,
        custom_attributes,
        manifest_resources,
        exported_types,
        target_frameworks,
        nested_classes,
        coverage: Coverage {
            state: "complete",
            issues: Vec::new(),
        },
        limitations,
    })
}

/// Selects the member facts already parsed for an inspection by exact
/// declaring-type names. The selection never reparses metadata or remaps
/// build-local tokens; it only projects the retained facts and reports names
/// that had no matching TypeDef.
pub fn inspect_managed_members<'a>(
    inspection: &'a Inspection,
    type_names: Option<&[String]>,
) -> ManagedMembersInspection<'a> {
    let selected_types = select_types(&inspection.types, type_names);
    let fields = select_fields(&inspection.fields, &selected_types, &inspection.types);
    let methods = select_methods(&inspection.methods, &selected_types, &inspection.types);
    let params = inspection
        .params
        .iter()
        .filter(|parameter| {
            parameter
                .method_token
                .as_ref()
                .is_some_and(|owner| methods.iter().any(|method| &method.token == owner))
        })
        .collect();
    let properties = select_properties(&inspection.properties, &selected_types);
    let events = select_events(&inspection.events, &selected_types);
    let generic_params =
        select_generic_params(&inspection.generic_params, &selected_types, &methods);
    let generic_constraints = inspection
        .generic_constraints
        .iter()
        .filter(|constraint| {
            generic_params
                .iter()
                .any(|parameter| parameter.token == constraint.owner_token)
        })
        .collect();
    let method_specs = inspection
        .method_specs
        .iter()
        .filter(|spec| {
            methods
                .iter()
                .any(|method| method.token == spec.method_token)
        })
        .collect();
    let (call_edges, field_accesses) = derive_member_edges(inspection, &methods);
    let unmatched_type_names = type_names
        .map(|names| {
            names
                .iter()
                .filter(|name| !selected_types.iter().any(|ty| type_name(ty) == **name))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    ManagedMembersInspection {
        module: inspection.module.as_ref(),
        assembly: inspection.assembly.as_ref(),
        references: &inspection.references,
        module_references: &inspection.module_references,
        exported_types: &inspection.exported_types,
        types: selected_types,
        fields,
        methods,
        params,
        properties,
        events,
        generic_params,
        generic_constraints,
        method_specs,
        member_references: &inspection.member_references,
        call_edges,
        field_accesses,
        selection: ManagedMembersSelection {
            type_names: type_names.map(|names| names.to_vec()),
            unmatched_type_names,
        },
    }
}

fn select_properties<'a>(
    properties: &'a [PropertyDefinition],
    selected_types: &[&TypeDefinition],
) -> Vec<&'a PropertyDefinition> {
    properties
        .iter()
        .filter(|property| {
            property
                .declaring_type_token
                .as_ref()
                .is_some_and(|owner| selected_types.iter().any(|ty| &ty.token == owner))
        })
        .collect()
}

fn select_events<'a>(
    events: &'a [EventDefinition],
    selected_types: &[&TypeDefinition],
) -> Vec<&'a EventDefinition> {
    events
        .iter()
        .filter(|event| {
            event
                .declaring_type_token
                .as_ref()
                .is_some_and(|owner| selected_types.iter().any(|ty| &ty.token == owner))
        })
        .collect()
}

fn select_generic_params<'a>(
    params: &'a [GenericParameter],
    selected_types: &[&TypeDefinition],
    selected_methods: &[&MethodDefinition],
) -> Vec<&'a GenericParameter> {
    params
        .iter()
        .filter(|parameter| {
            selected_types
                .iter()
                .any(|ty| ty.token == parameter.owner_token)
                || selected_methods
                    .iter()
                    .any(|method| method.token == parameter.owner_token)
        })
        .collect()
}

fn derive_member_edges(
    inspection: &Inspection,
    methods: &[&MethodDefinition],
) -> (Vec<CallEdge>, Vec<FieldAccess>) {
    let mut calls = Vec::new();
    let mut fields = Vec::new();

    for method in methods {
        let caller = member_declaring_type_name(inspection, &method.token)
            .map(|owner| format!("{owner}.{}", method.name));
        for anchor in &method.body.anchors {
            let Some(target_token) = anchor.operand.as_deref() else {
                continue;
            };
            if anchor.opcode == "0xd0" {
                continue;
            }
            match anchor.operand_kind {
                "method" => {
                    let (target_name, target_declaring_type) =
                        method_target(inspection, target_token);
                    calls.push(CallEdge {
                        caller_token: method.token.clone(),
                        caller: caller.clone().or_else(|| Some(method.name.clone())),
                        opcode: anchor.opcode.clone(),
                        target_token: target_token.to_owned(),
                        target_kind: target_kind(target_token),
                        target_name,
                        target_declaring_type,
                    });
                }
                "field" => {
                    let (field_name, field_declaring_type) = field_target(inspection, target_token);
                    fields.push(FieldAccess {
                        method_token: method.token.clone(),
                        method: caller.clone().or_else(|| Some(method.name.clone())),
                        opcode: anchor.opcode.clone(),
                        field_token: target_token.to_owned(),
                        field_name,
                        field_declaring_type,
                    });
                }
                _ => {}
            }
        }
    }

    (calls, fields)
}

fn project_member_ownership(
    types: &[TypeDefinition],
    fields: &mut [FieldDefinition],
    methods: &mut [MethodDefinition],
) {
    for field in fields {
        if let Some(owner) = owner_for_member_row(types, 4, &field.token) {
            field.declaring_type_token = Some(owner.token.clone());
            field.declaring_type = Some(type_name(owner));
        }
    }
    for method in methods {
        if let Some(owner) = owner_for_member_row(types, 6, &method.token) {
            method.declaring_type_token = Some(owner.token.clone());
            method.declaring_type = Some(type_name(owner));
        }
    }
}

fn owner_for_member_row<'a>(
    types: &'a [TypeDefinition],
    table: u32,
    member_token: &str,
) -> Option<&'a TypeDefinition> {
    let (_, row) = decode_token(member_token)?;
    if !matches!(table, 4 | 6) {
        return None;
    }
    let next = types
        .iter()
        .map(|ty| member_list(ty, table))
        .filter(|start| *start > row)
        .min()
        .unwrap_or(u32::MAX);
    types
        .iter()
        .find(|ty| member_list(ty, table) <= row && row < next)
}

fn project_member_reference_parents(
    references: &mut [MemberReference],
    types: &[TypeDefinition],
    type_references: &[TypeReference],
    _type_specs: &[TypeSpecification],
) {
    for reference in references {
        let Some(parent_token) = reference.parent_token.as_deref() else {
            continue;
        };
        reference.parent_name = if let Some(ty) = types.iter().find(|ty| ty.token == parent_token) {
            Some(type_name(ty))
        } else if let Some(ty) = type_references.iter().find(|ty| ty.token == parent_token) {
            Some(qualified_type_reference_name(ty))
        } else if let Some(spec) = _type_specs.iter().find(|spec| spec.token == parent_token) {
            (spec.signature.parse_status == "decoded")
                .then(|| spec.signature.field_type.clone())
                .flatten()
        } else {
            None
        };
    }
}

fn target_frameworks(
    attributes: &[CustomAttribute],
    member_references: &[MemberReference],
) -> Vec<String> {
    let mut frameworks = Vec::new();
    for attribute in attributes {
        let Some(parent_token) = attribute.parent_token.as_deref() else {
            continue;
        };
        if !parent_token.starts_with("0x200000") {
            continue;
        }
        let Some(constructor_token) = attribute.constructor_token.as_deref() else {
            continue;
        };
        let Some(constructor) = member_references
            .iter()
            .find(|reference| reference.token == constructor_token)
        else {
            continue;
        };
        if constructor.parent_name.as_deref()
            != Some("System.Runtime.Versioning.TargetFrameworkAttribute")
        {
            continue;
        }
        if let Some(value) = attribute.decoded_fixed_string.as_deref() {
            if !frameworks.iter().any(|existing| existing == value) {
                frameworks.push(value.to_owned());
            }
        }
    }
    frameworks
}

fn runtime_family(
    frameworks: &[String],
    references: &[AssemblyReference],
    cli_flags: u32,
) -> &'static str {
    if cli_flags & 1 == 0 {
        return "mixed-clr-native";
    }
    if references.iter().any(|reference| {
        reference.name == "UnityEngine" || reference.name.starts_with("UnityEngine.")
    }) {
        return "unity-mono";
    }
    if frameworks
        .iter()
        .any(|framework| framework.starts_with(".NETFramework,"))
    {
        return "dotnet-framework";
    }
    if frameworks
        .iter()
        .any(|framework| framework.starts_with(".NETCoreApp,"))
    {
        return "modern-dotnet";
    }
    "unknown"
}

fn qualified_type_reference_name(reference: &TypeReference) -> String {
    if reference.namespace.is_empty() {
        reference.name.clone()
    } else {
        format!("{}.{}", reference.namespace, reference.name)
    }
}

fn target_kind(token: &str) -> &'static str {
    match token.get(0..4) {
        Some("0x06") => "method-def",
        Some("0x0a") => "member-ref",
        Some("0x2b") => "method-spec",
        _ => "unknown",
    }
}

fn method_target(inspection: &Inspection, token: &str) -> (Option<String>, Option<String>) {
    if let Some(method) = inspection
        .methods
        .iter()
        .find(|method| method.token == token)
    {
        return (
            Some(method.name.clone()),
            member_declaring_type_name(inspection, token),
        );
    }
    if let Some(reference) = inspection
        .member_references
        .iter()
        .find(|reference| reference.token == token)
    {
        return (Some(reference.name.clone()), None);
    }
    if let Some(spec) = inspection
        .method_specs
        .iter()
        .find(|spec| spec.token == token)
    {
        return method_target(inspection, &spec.method_token);
    }
    (None, None)
}

fn field_target(inspection: &Inspection, token: &str) -> (Option<String>, Option<String>) {
    let Some(field) = inspection.fields.iter().find(|field| field.token == token) else {
        return (None, None);
    };
    (
        Some(field.name.clone()),
        member_declaring_type_name(inspection, token),
    )
}

fn member_declaring_type_name(inspection: &Inspection, member_token: &str) -> Option<String> {
    let (table, row) = decode_token(member_token)?;
    if !matches!(table, 4 | 6) {
        return None;
    }
    let next = inspection
        .types
        .iter()
        .map(|ty| member_list(ty, table))
        .filter(|start| *start > row)
        .min()
        .unwrap_or_else(|| match table {
            4 => inspection.fields.len() as u32 + 1,
            6 => inspection.methods.len() as u32 + 1,
            _ => 0,
        });
    inspection
        .types
        .iter()
        .find(|ty| member_list(ty, table) <= row && row < next)
        .map(type_name)
}

fn member_list(ty: &TypeDefinition, table: u32) -> u32 {
    match table {
        4 => ty.field_list.first_row.unwrap_or(0),
        6 => ty.method_list.first_row.unwrap_or(0),
        _ => 0,
    }
}

fn project_member_list_ranges(
    types: &mut [TypeDefinition],
    field_count: usize,
    method_count: usize,
) {
    project_one_member_list(types, 4, field_count);
    project_one_member_list(types, 6, method_count);
}

fn project_one_member_list(types: &mut [TypeDefinition], table: u32, total: usize) {
    for index in 0..types.len() {
        let first = member_list(&types[index], table);
        let next = types
            .iter()
            .skip(index + 1)
            .map(|ty| member_list(ty, table))
            .find(|row| *row > first)
            .unwrap_or(total.saturating_add(1) as u32);
        let list = match table {
            4 => &mut types[index].field_list,
            6 => &mut types[index].method_list,
            _ => continue,
        };
        if first == 0 || first >= next || first as usize > total {
            list.first_row = None;
            list.last_row = None;
            list.count = 0;
            continue;
        }
        let last_exclusive = next.min(total.saturating_add(1) as u32);
        list.first_row = Some(first);
        list.last_row = Some(last_exclusive.saturating_sub(1));
        list.count = last_exclusive.saturating_sub(first);
    }
}

fn select_types<'a>(
    types: &'a [TypeDefinition],
    type_names: Option<&[String]>,
) -> Vec<&'a TypeDefinition> {
    match type_names {
        None => types.iter().collect(),
        Some(names) => types
            .iter()
            .filter(|ty| names.iter().any(|name| type_name(ty) == *name))
            .collect(),
    }
}

fn type_name(ty: &TypeDefinition) -> String {
    if !ty.full_name.is_empty() {
        return ty.full_name.clone();
    }
    if ty.enclosing_type_token.is_some() {
        ty.name.clone()
    } else if ty.namespace.is_empty() {
        ty.name.clone()
    } else {
        format!("{}.{}", ty.namespace, ty.name)
    }
}

fn select_fields<'a>(
    fields: &'a [FieldDefinition],
    selected_types: &[&TypeDefinition],
    all_types: &[TypeDefinition],
) -> Vec<&'a FieldDefinition> {
    select_list_rows(
        fields,
        selected_types,
        all_types,
        |ty| ty.field_list.first_row.unwrap_or(0),
        |field| decode_token(&field.token).map(|(_, row)| row),
    )
}

fn select_methods<'a>(
    methods: &'a [MethodDefinition],
    selected_types: &[&TypeDefinition],
    all_types: &[TypeDefinition],
) -> Vec<&'a MethodDefinition> {
    select_list_rows(
        methods,
        selected_types,
        all_types,
        |ty| ty.method_list.first_row.unwrap_or(0),
        |method| decode_token(&method.token).map(|(_, row)| row),
    )
}

fn select_list_rows<'a, T, FRow, FStart>(
    rows: &'a [T],
    selected_types: &[&TypeDefinition],
    all_types: &[TypeDefinition],
    start: FStart,
    row_number: FRow,
) -> Vec<&'a T>
where
    FRow: Fn(&T) -> Option<u32>,
    FStart: Fn(&TypeDefinition) -> u32,
{
    let mut selected = Vec::new();
    for ty in selected_types {
        let first = start(ty);
        if first == 0 {
            continue;
        }
        let last = all_types
            .iter()
            .filter_map(|candidate| {
                let candidate_first = start(candidate);
                (candidate_first > first).then_some(candidate_first - 1)
            })
            .min()
            .unwrap_or(u32::MAX);
        selected.extend(
            rows.iter().filter(|row| {
                row_number(row).is_some_and(|number| number >= first && number <= last)
            }),
        );
    }
    selected
}

struct PeLayout {
    machine: u16,
    characteristics: u16,
    headers: usize,
    cli_rva: u32,
    sections: Vec<Section>,
    debug_rva: u32,
    debug_size: u32,
}
struct Section {
    va: u32,
    raw: u32,
    size: u32,
}
impl PeLayout {
    fn read(b: &[u8]) -> Result<Self, Error> {
        if u16(b, 0)? != 0x5a4d {
            return Err(Error::Malformed("expected an MZ PE image"));
        }
        let pe = u32(b, 60)? as usize;
        if u32(b, pe)? != 0x0000_4550 {
            return Err(Error::Malformed("expected a PE signature"));
        }
        let machine = u16(b, pe + 4)?;
        let count = u16(b, pe + 6)? as usize;
        let optional_size = u16(b, pe + 20)? as usize;
        let opt = pe + 24;
        let magic = u16(b, opt)?;
        let dir_base = match magic {
            0x10b => 96,
            0x20b => 112,
            _ => return Err(Error::Unsupported("unsupported PE optional header magic")),
        };
        let headers = u32(b, opt + 60)? as usize;
        let directories = u32(b, opt + dir_base - 4)? as usize;
        if directories <= 14 || optional_size < dir_base + 15 * 8 {
            return Err(Error::Malformed("PE has no CLI data directory"));
        }
        let cli_rva = u32(b, opt + dir_base + 14 * 8)?;
        let cli_size = u32(b, opt + dir_base + 14 * 8 + 4)?;
        let debug_rva = if directories > 6 {
            u32(b, opt + dir_base + 6 * 8)?
        } else {
            0
        };
        let debug_size = if directories > 6 {
            u32(b, opt + dir_base + 6 * 8 + 4)?
        } else {
            0
        };
        if cli_rva == 0 || cli_size < 24 {
            return Err(Error::Malformed("PE CLI directory is absent or truncated"));
        }
        let sections_at = opt + optional_size;
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let at = sections_at + i * 40;
            sections.push(Section {
                va: u32(b, at + 12)?,
                raw: u32(b, at + 20)?,
                size: u32(b, at + 16)?,
            });
        }
        Ok(Self {
            machine,
            characteristics: u16(b, pe + 22)?,
            headers,
            cli_rva,
            sections,
            debug_rva,
            debug_size,
        })
    }
    fn map(&self, b: &[u8], rva: u32, size: usize) -> Result<usize, Error> {
        let start = rva as usize;
        if start < self.headers {
            if start.checked_add(size).is_some_and(|e| e <= b.len()) {
                return Ok(start);
            }
        }
        for s in &self.sections {
            if rva >= s.va && rva - s.va < s.size {
                let at = s.raw as usize + (rva - s.va) as usize;
                if at.checked_add(size).is_some_and(|e| e <= b.len()) {
                    return Ok(at);
                }
            }
        }
        Err(Error::Malformed("CLI RVA is not backed by a PE section"))
    }

    fn available_bytes(&self, b: &[u8], rva: u32) -> Result<(usize, usize), Error> {
        let start = rva as usize;
        if start < self.headers {
            return Ok((start, b.len().saturating_sub(start)));
        }
        for section in &self.sections {
            if rva < section.va || rva - section.va >= section.size {
                continue;
            }
            let offset = section.raw as usize + (rva - section.va) as usize;
            if offset >= b.len() {
                return Err(Error::Malformed("FieldRVA points outside file bytes"));
            }
            let section_remaining = (section.size - (rva - section.va)) as usize;
            return Ok((offset, section_remaining.min(b.len() - offset)));
        }
        Err(Error::Malformed("FieldRVA is not backed by a PE section"))
    }
}

struct MetadataRoot {
    version: String,
    stream_names: Vec<String>,
    row_counts: std::collections::BTreeMap<String, u32>,
    tables: Option<TableStream>,
    strings: Vec<u8>,
    guids: Vec<u8>,
    blobs: Vec<u8>,
    user_strings: Vec<u8>,
}
struct Stream {
    offset: usize,
}
struct TableStream {
    offset: usize,
    valid: u64,
    rows: Vec<u32>,
    heap_sizes: u8,
}
impl MetadataRoot {
    fn read(b: &[u8]) -> Result<Self, Error> {
        if u32(b, 0)? != 0x424a_5342 {
            return Err(Error::Malformed("invalid CLI metadata signature"));
        }
        let version_len = u32(b, 12)? as usize;
        let version = String::from_utf8_lossy(slice(b, 16, version_len)?)
            .trim_end_matches('\0')
            .to_owned();
        let mut at = (16 + version_len + 3) & !3;
        let streams = u16(b, at + 2)? as usize;
        at += 4;
        let mut names = Vec::new();
        let mut map = std::collections::BTreeMap::new();
        let mut tables = None;
        let mut strings = Vec::new();
        let mut guids = Vec::new();
        let mut blobs = Vec::new();
        let mut user_strings = Vec::new();
        for _ in 0..streams {
            let offset = u32(b, at)? as usize;
            let size = u32(b, at + 4)? as usize;
            let name_end = slice(b, at + 8, 32)?
                .iter()
                .position(|x| *x == 0)
                .unwrap_or(32);
            let name = String::from_utf8_lossy(&slice(b, at + 8, name_end)?).to_string();
            names.push(name.clone());
            let stream = Stream { offset };
            if name == "#Strings" {
                strings = slice(b, offset, size)?.to_vec();
            } else if name == "#GUID" {
                guids = slice(b, offset, size)?.to_vec();
            } else if name == "#Blob" {
                blobs = slice(b, offset, size)?.to_vec();
            } else if name == "#US" {
                user_strings = slice(b, offset, size)?.to_vec();
            } else if name == "#~" || name == "#-" {
                tables = Some(Self::table_stream(b, stream)?);
            }
            at += 8 + ((name_end + 1 + 3) & !3);
        }
        if let Some(t) = &tables {
            for (i, count) in t.rows.iter().enumerate() {
                if t.valid & (1u64 << i) != 0 {
                    map.insert(i.to_string(), *count);
                }
            }
        }
        Ok(Self {
            version,
            stream_names: names,
            row_counts: map,
            tables,
            strings,
            guids,
            blobs,
            user_strings,
        })
    }
    fn table_stream(b: &[u8], s: Stream) -> Result<TableStream, Error> {
        let o = s.offset;
        let heap_sizes = *slice(b, o + 6, 1)?.first().unwrap();
        let valid = u64::from_le_bytes(
            slice(b, o + 8, 8)?
                .try_into()
                .map_err(|_| Error::Malformed("truncated table stream"))?,
        );
        let mut at = o + 24;
        let mut rows = vec![0u32; 64];
        for i in 0..64 {
            if valid & (1u64 << i) != 0 {
                rows[i] = u32(b, at)?;
                at += 4;
            }
        }
        Ok(TableStream {
            offset: o,
            valid,
            rows,
            heap_sizes,
        })
    }
    fn strings(&self, index: usize) -> String {
        if index == 0 || index >= self.strings.len() {
            return String::new();
        }
        let end = self.strings[index..]
            .iter()
            .position(|x| *x == 0)
            .unwrap_or(self.strings.len() - index);
        String::from_utf8_lossy(&self.strings[index..index + end]).to_string()
    }
    fn guid(&self, index: usize) -> Option<String> {
        if index == 0 {
            return None;
        }
        let at = (index - 1).checked_mul(16)?;
        let g = self.guids.get(at..at + 16)?;
        Some(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
            g[3],
            g[2],
            g[1],
            g[0],
            g[5],
            g[4],
            g[7],
            g[6],
            g[8],
            g[9],
            hex(&g[10..])
        ))
    }
    fn indexes(&self) -> (usize, usize, usize) {
        (
            if self.tables.as_ref().is_some_and(|t| t.heap_sizes & 1 != 0) {
                4
            } else {
                2
            },
            if self.tables.as_ref().is_some_and(|t| t.heap_sizes & 2 != 0) {
                4
            } else {
                2
            },
            if self.tables.as_ref().is_some_and(|t| t.heap_sizes & 4 != 0) {
                4
            } else {
                2
            },
        )
    }
    fn module(&self, b: &[u8], pe: &PeLayout) -> Option<Module> {
        let t = self.tables.as_ref()?;
        if t.rows[0] == 0 {
            return None;
        }
        let (s, g, _) = self.indexes();
        let mut at = table_start(t, 0);
        let row_offset = Some(at);
        let generation = u16(b, at).ok()?;
        at += 2;
        let name = read_index(b, &mut at, s).ok()?;
        let mvid = read_index(b, &mut at, g).ok()?;
        let enc = read_index(b, &mut at, g).ok()?;
        let enc_base = read_index(b, &mut at, g).ok()?;
        let _ = pe;
        Some(Module {
            row_offset,
            name: self.strings(name),
            generation,
            mvid: self.guid(mvid),
            enc_id: self.guid(enc),
            enc_base_id: self.guid(enc_base),
            token: "0x00000001".into(),
        })
    }
    fn assembly(&self, b: &[u8], _pe: &PeLayout) -> Option<Assembly> {
        let t = self.tables.as_ref()?;
        if t.rows[32] == 0 {
            return None;
        }
        let (s, _, blob) = self.indexes();
        let at = table_start(t, 32);
        let row_offset = Some(at);
        let hash_algorithm = u32(b, at).ok()?;
        let flags = u32(b, at + 4).ok()?;
        let major = u16(b, at + 8).ok()?;
        let minor = u16(b, at + 10).ok()?;
        let build = u16(b, at + 12).ok()?;
        let rev = u16(b, at + 14).ok()?;
        let mut p = at + 16;
        let public_key_offset = read_index(b, &mut p, blob).ok()?;
        let public_key = blob_value(&self.blobs, public_key_offset);
        let name = read_index(b, &mut p, s).ok()?;
        let culture = read_index(b, &mut p, s).ok()?;
        let public_key_identity =
            assembly_public_key_identity(flags, public_key_offset, public_key.as_deref());
        Some(Assembly {
            row_offset,
            name: self.strings(name),
            version: format!("{major}.{minor}.{build}.{rev}"),
            culture: (culture != 0).then(|| self.strings(culture)),
            flags,
            hash_algorithm,
            public_key_offset: Some(public_key_offset),
            public_key_kind: public_key_identity.kind,
            public_key_byte_length: public_key_identity.byte_length,
            public_key_sha256: public_key_identity.sha256,
            public_key_token: public_key_identity.token,
            token: "0x20000001".into(),
            custom_attributes: Vec::new(),
        })
    }
    fn references(&self, b: &[u8], _pe: &PeLayout) -> Vec<AssemblyReference> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (s, _, blob) = self.indexes();
        let mut out = Vec::new();
        let mut at = table_start(t, 35);
        for row in 1..=t.rows[35] {
            let major = u16(b, at).unwrap_or(0);
            let minor = u16(b, at + 2).unwrap_or(0);
            let build = u16(b, at + 4).unwrap_or(0);
            let rev = u16(b, at + 6).unwrap_or(0);
            let flags = u32(b, at + 8).unwrap_or(0);
            let public_key_or_token_offset = read_index(b, &mut at, blob).ok();
            let name = read_index(b, &mut at, s).unwrap_or(0);
            let culture = read_index(b, &mut at, s).unwrap_or(0);
            let hash_value_offset = read_index(b, &mut at, blob).ok();
            let public_key_or_token_hex = public_key_or_token_offset
                .and_then(|offset| blob_value(&self.blobs, offset))
                .map(|value| hex(&value));
            let hash_value_hex = hash_value_offset
                .and_then(|offset| blob_value(&self.blobs, offset))
                .map(|value| hex(&value));
            let issue = (public_key_or_token_offset.is_none() || hash_value_offset.is_none())
                .then_some("truncated AssemblyRef row".to_owned())
                .or_else(|| {
                    (public_key_or_token_offset
                        .is_some_and(|offset| offset != 0 && public_key_or_token_hex.is_none())
                        || hash_value_offset
                            .is_some_and(|offset| offset != 0 && hash_value_hex.is_none()))
                    .then_some("AssemblyRef blob index is outside #Blob".to_owned())
                });
            out.push(AssemblyReference {
                name: self.strings(name),
                version: format!("{major}.{minor}.{build}.{rev}"),
                culture: (culture != 0).then(|| self.strings(culture)),
                flags,
                token: token(35, row),
                public_key_or_token_offset,
                public_key_or_token_hex,
                hash_value_offset,
                hash_value_hex,
                issue,
            });
        }
        out
    }
    fn impl_maps(&self, b: &[u8]) -> Vec<ImplMap> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[28] == 0 {
            return Vec::new();
        }
        let (strings, _, _) = self.indexes();
        let forwarded_width = coded_width(t, 1, &[4, 6]);
        let module_width = table_index_width(t, 26);
        let mut at = table_start(t, 28);
        let mut out = Vec::new();
        for row in 1..=t.rows[28] {
            let source_offset = Some(at);
            let flags = u16(b, at).ok();
            let (flag_names, unknown_flags) = flags.map(decode_impl_map_flags).unwrap_or_default();
            at += 2;
            let raw_member_forwarded = read_index(b, &mut at, forwarded_width).ok();
            let import_name = read_index(b, &mut at, strings).ok();
            let module = read_index(b, &mut at, module_width).ok();
            let member_token = raw_member_forwarded.and_then(|value| {
                let table = [4u32, 6].get(value & 1).copied()?;
                let row = value >> 1;
                (row != 0).then(|| token(table, row as u32))
            });
            let module_token = module
                .filter(|value| *value != 0)
                .map(|value| token(26, value as u32));
            let issue = if flags.is_none()
                || raw_member_forwarded.is_none()
                || import_name.is_none()
                || module.is_none()
            {
                Some("truncated ImplMap row".to_owned())
            } else if raw_member_forwarded == Some(0)
                || raw_member_forwarded.is_some_and(|value| {
                    let table = if value & 1 == 0 { 4 } else { 6 };
                    let row = value >> 1;
                    row == 0 || row > t.rows[table] as usize
                })
            {
                Some("ImplMap member reference is out of range".to_owned())
            } else if module == Some(0) || module.is_some_and(|value| value > t.rows[26] as usize) {
                Some("ImplMap ModuleRef reference is out of range".to_owned())
            } else {
                None
            };
            out.push(ImplMap {
                token: token(28, row),
                source_offset,
                flags,
                flag_names,
                unknown_flags,
                raw_member_forwarded,
                member_token,
                import_name: import_name
                    .map(|value| self.strings(value))
                    .unwrap_or_default(),
                module_token,
                issue,
            });
        }
        out
    }

    fn module_references(&self, b: &[u8]) -> Vec<ModuleReference> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (strings, _, _) = self.indexes();
        let mut at = table_start(t, 26);
        let mut out = Vec::new();
        for row in 1..=t.rows[26] {
            let source_offset = Some(at);
            let name = read_index(b, &mut at, strings).ok();
            out.push(ModuleReference {
                source_offset,
                name: name.map(|value| self.strings(value)).unwrap_or_default(),
                token: token(26, row),
                issue: name
                    .is_none()
                    .then_some("truncated ModuleRef row".to_owned()),
            });
        }
        out
    }
    fn signature(&self, index: usize, kind: &'static str) -> Signature {
        let raw = blob_value(&self.blobs, index).unwrap_or_default();
        let mut signature = Signature {
            raw_length: raw.len(),
            raw_sha256: digest(&raw),
            resolved_sha256: None,
            parse_status: if raw.is_empty() {
                "malformed"
            } else {
                "unsupported"
            },
            calling_convention: None,
            generic_parameter_count: None,
            parameter_count: None,
            return_type: None,
            parameter_types: Vec::new(),
            field_type: None,
            local_types: Vec::new(),
            issue: None,
        };
        if raw.is_empty() {
            signature.issue = Some("signature blob is empty or out of bounds".into());
            return signature;
        }
        let mut at = 0;
        if matches!(kind, "field" | "type-spec") {
            signature.field_type = decode_type(&raw, &mut at);
            signature.parse_status = if at == raw.len() {
                "decoded"
            } else {
                "partial"
            };
            if signature.parse_status == "decoded" {
                signature.resolved_sha256 = Some(digest(
                    signature
                        .field_type
                        .as_deref()
                        .unwrap_or_default()
                        .as_bytes(),
                ));
            }
            return signature;
        }
        let call = raw[at];
        at += 1;
        if kind == "local" {
            signature.calling_convention = Some(format!("0x{call:02x}"));
            let Some(count) = compressed(&raw, &mut at) else {
                signature.issue = Some("local signature variable count is truncated".into());
                return signature;
            };
            signature.parameter_count = Some(count);
            for _ in 0..count.min(1024) {
                let Some(value) = decode_type(&raw, &mut at) else {
                    signature.issue =
                        Some("local signature type is unsupported or truncated".into());
                    signature.parse_status = "partial";
                    return signature;
                };
                signature.local_types.push(value);
            }
            signature.parse_status = if at == raw.len() {
                "decoded"
            } else {
                "partial"
            };
            if signature.parse_status == "decoded" {
                signature.resolved_sha256 =
                    Some(digest(signature.local_types.join("|").as_bytes()));
            }
            return signature;
        }
        signature.calling_convention = Some(format!("0x{call:02x}"));
        if call & 0x10 != 0 {
            signature.generic_parameter_count = compressed(&raw, &mut at);
        }
        signature.parameter_count = compressed(&raw, &mut at);
        signature.return_type = decode_type(&raw, &mut at);
        let count = signature.parameter_count.unwrap_or(0);
        for _ in 0..count.min(1024) {
            if let Some(value) = decode_type(&raw, &mut at) {
                signature.parameter_types.push(value);
            } else {
                break;
            }
        }
        signature.parse_status = if at == raw.len() {
            "decoded"
        } else {
            "partial"
        };
        if at < raw.len() {
            signature.issue = Some("signature contains unsupported or trailing bytes".into());
        }
        if signature.parse_status == "decoded" {
            let resolved = [
                signature.return_type.as_deref().unwrap_or_default(),
                &signature.parameter_types.join("|"),
            ]
            .join(";");
            signature.resolved_sha256 = Some(digest(resolved.as_bytes()));
        }
        signature
    }
    fn type_references(&self, b: &[u8]) -> Vec<TypeReference> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[1] == 0 {
            return Vec::new();
        }

        let (strings, _, _) = self.indexes();
        let scope_width = coded_width(t, 2, &[0, 1, 26, 35]);
        let mut at = table_start(t, 1);
        let mut out = Vec::new();

        for row in 1..=t.rows[1] {
            let source_offset = Some(at);
            let name = read_index(b, &mut at, strings).ok();
            let namespace = read_index(b, &mut at, strings).ok();
            let raw_scope = read_index(b, &mut at, scope_width).ok();
            let tag = raw_scope.map(|value| value & 0x3);
            let scope_row = raw_scope.map(|value| value >> 2);
            let (resolution_scope_kind, target_table) = match tag {
                Some(0) => (Some("Module"), Some(0usize)),
                Some(1) => (Some("TypeRef"), Some(1usize)),
                Some(2) => (Some("ModuleRef"), Some(26usize)),
                Some(3) => (Some("AssemblyRef"), Some(35usize)),
                _ => (None, None),
            };
            let issue = if name.is_none() || namespace.is_none() || raw_scope.is_none() {
                Some("truncated TypeRef row".to_owned())
            } else if raw_scope == Some(0) {
                Some("TypeRef resolution scope is null".to_owned())
            } else if target_table.is_none() {
                Some("TypeRef resolution scope tag is unsupported".to_owned())
            } else if scope_row == Some(0)
                || scope_row.is_some_and(|value| value > t.rows[target_table.unwrap()] as usize)
            {
                Some("TypeRef resolution scope is out of range".to_owned())
            } else {
                None
            };
            out.push(TypeReference {
                token: token(1, row),
                source_offset,
                name: name.map(|value| self.strings(value)).unwrap_or_default(),
                namespace: namespace
                    .map(|value| self.strings(value))
                    .unwrap_or_default(),
                raw_resolution_scope: raw_scope,
                resolution_scope_kind,
                resolution_scope_token: match (target_table, scope_row) {
                    (Some(table), Some(row)) if row != 0 => Some(token(table as u32, row as u32)),
                    _ => None,
                },
                issue,
            });
        }

        out
    }

    fn types(&self, b: &[u8]) -> Vec<TypeDefinition> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[2] == 0 {
            return Vec::new();
        }
        let (s, _, _) = self.indexes();
        let coded = coded_width(t, 2, &[1, 2, 27]);
        let mut at = table_start(t, 2);
        let mut out = Vec::new();
        for row in 1..=t.rows[2] {
            let row_offset = Some(at);
            let flags = u32(b, at).unwrap_or(0);
            at += 4;
            let name = read_index(b, &mut at, s).unwrap_or(0);
            let namespace = read_index(b, &mut at, s).unwrap_or(0);
            let extends = read_index(b, &mut at, coded).unwrap_or(0);
            let field_list = read_index(b, &mut at, table_index_width(t, 4)).unwrap_or(0) as u32;
            let method_list = read_index(b, &mut at, table_index_width(t, 6)).unwrap_or(0) as u32;
            out.push(TypeDefinition {
                token: token(2, row),
                row_offset,
                name: self.strings(name),
                namespace: self.strings(namespace),
                full_name: String::new(),
                name_sha256: None,
                flags,
                extends_token: (extends != 0).then(|| format!("0x{:08x}", extends)),
                field_list: MemberList {
                    first_row: (field_list != 0).then_some(field_list),
                    last_row: None,
                    count: 0,
                },
                method_list: MemberList {
                    first_row: (method_list != 0).then_some(method_list),
                    last_row: None,
                    count: 0,
                },
                custom_attributes: Vec::new(),
                interface_impl_tokens: Vec::new(),
                method_impl_tokens: Vec::new(),
                enclosing_type_token: None,
                nested_type_tokens: Vec::new(),
            });
        }
        out
    }
    fn field_layouts(&self, b: &[u8]) -> Vec<FieldLayout> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[16] == 0 {
            return Vec::new();
        }

        let width = table_index_width(t, 4);
        let mut at = table_start(t, 16);
        let mut out = Vec::new();
        for row in 1..=t.rows[16] {
            let source_offset = Some(at);
            let offset = u32(b, at).ok();
            at += 4;
            let field = read_index(b, &mut at, width).ok();
            let issue = if offset.is_none() || field.is_none() {
                Some("truncated FieldLayout row".to_owned())
            } else if field == Some(0) || field.is_some_and(|value| value > t.rows[4] as usize) {
                Some("FieldLayout field reference is out of range".to_owned())
            } else {
                None
            };
            out.push(FieldLayout {
                token: token(16, row),
                source_offset,
                field_token: field
                    .filter(|value| *value != 0)
                    .map(|value| token(4, value as u32)),
                offset,
                issue,
            });
        }
        out
    }

    fn field_rvas(&self, b: &[u8]) -> Vec<FieldRva> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[29] == 0 {
            return Vec::new();
        }

        let width = table_index_width(t, 4);
        let mut at = table_start(t, 29);
        let mut out = Vec::new();
        for row in 1..=t.rows[29] {
            let source_offset = Some(at);
            let rva = u32(b, at).ok();
            at += 4;
            let field = read_index(b, &mut at, width).ok();
            let issue = if rva.is_none() || field.is_none() {
                Some("truncated FieldRVA row".to_owned())
            } else if field == Some(0) || field.is_some_and(|value| value > t.rows[4] as usize) {
                Some("FieldRVA field reference is out of range".to_owned())
            } else if rva == Some(0) {
                Some("FieldRVA has a null RVA".to_owned())
            } else {
                None
            };
            out.push(FieldRva {
                token: token(29, row),
                source_offset,
                field_token: field
                    .filter(|value| *value != 0)
                    .map(|value| token(4, value as u32)),
                rva,
                data_offset: None,
                data_hex: None,
                issue,
            });
        }
        out
    }

    fn fields(&self, b: &[u8]) -> Vec<FieldDefinition> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[4] == 0 {
            return Vec::new();
        }
        let (s, _, blob) = self.indexes();
        let mut at = table_start(t, 4);
        let mut out = Vec::new();
        for row in 1..=t.rows[4] {
            let source_offset = Some(at);
            let flags = u16(b, at).unwrap_or(0);
            at += 2;
            let name = read_index(b, &mut at, s).unwrap_or(0);
            let sig = read_index(b, &mut at, blob).unwrap_or(0);
            out.push(FieldDefinition {
                token: token(4, row),
                source_offset,
                declaring_type_token: None,
                declaring_type: None,
                name: self.strings(name),
                flags,
                signature: self.signature(sig, "field"),
                constants: Vec::new(),
                rva: None,
                data_offset: None,
                data_hex: None,
                layout_offset: None,
                custom_attributes: Vec::new(),
                issue: None,
            });
        }
        out
    }
    fn methods(&self, b: &[u8], pe: &PeLayout) -> Vec<MethodDefinition> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[6] == 0 {
            return Vec::new();
        }
        let (s, _, blob) = self.indexes();
        let mut at = table_start(t, 6);
        let mut out = Vec::new();
        for row in 1..=t.rows[6] {
            let source_offset = Some(at);
            let rva = u32(b, at).unwrap_or(0);
            let impl_flags = u16(b, at + 4).unwrap_or(0);
            let flags = u16(b, at + 6).unwrap_or(0);
            at += 8;
            let name = read_index(b, &mut at, s).unwrap_or(0);
            let sig = read_index(b, &mut at, blob).unwrap_or(0);
            let param_list = read_index(b, &mut at, table_index_width(t, 8)).unwrap_or(0) as u32;
            let (impl_code_type, impl_managed_status, impl_flag_names, impl_unknown_flags) =
                decode_method_impl_flags(impl_flags);
            out.push(MethodDefinition {
                token: token(6, row),
                source_offset,
                declaring_type_token: None,
                declaring_type: None,
                name: self.strings(name),
                rva,
                impl_flags,
                impl_code_type,
                impl_managed_status,
                impl_flag_names,
                impl_unknown_flags,
                flags,
                signature: self.signature(sig, "method"),
                body: method_body(b, pe, rva),
                param_list,
                custom_attributes: Vec::new(),
                impl_map_token: None,
                pinvoke_module_token: None,
                pinvoke_import_name: None,
                pinvoke_flags: None,
            });
        }
        out
    }
    fn member_references(&self, b: &[u8]) -> Vec<MemberReference> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[10] == 0 {
            return Vec::new();
        }
        let (s, _, blob) = self.indexes();
        let parent = coded_width(t, 3, &[1, 2, 6, 27]);
        let mut at = table_start(t, 10);
        let mut out = Vec::new();
        for row in 1..=t.rows[10] {
            let row_offset = Some(at);
            let parent_value = read_index(b, &mut at, parent).unwrap_or(0);
            let name = read_index(b, &mut at, s).unwrap_or(0);
            let sig = read_index(b, &mut at, blob).unwrap_or(0);
            out.push(MemberReference {
                token: token(10, row),
                row_offset,
                name: self.strings(name),
                parent_token: (parent_value != 0)
                    .then(|| coded_token(parent_value, 3, &[1, 2, 6, 27])),
                parent_name: None,
                signature: self.signature(sig, "member-ref"),
            });
        }
        out
    }
    fn params(&self, b: &[u8]) -> Vec<ParameterDefinition> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (s, _, _) = self.indexes();
        let mut at = table_start(t, 8);
        let mut out = Vec::new();
        for row in 1..=t.rows[8] {
            let source_offset = Some(at);
            let flags = u16(b, at).ok();
            let sequence = u16(b, at + 2).ok();
            at += 4;
            let name = read_index(b, &mut at, s).ok();
            let issue = if flags.is_none() || sequence.is_none() || name.is_none() {
                Some("truncated Param row".to_owned())
            } else if name.is_some_and(|index| index != 0 && index >= self.strings.len()) {
                Some("Param name index is outside #Strings".to_owned())
            } else {
                None
            };
            out.push(ParameterDefinition {
                token: token(8, row),
                source_offset,
                flags: flags.unwrap_or(0),
                sequence: sequence.unwrap_or(0),
                name: self.strings(name.unwrap_or(0)),
                constants: Vec::new(),
                method_token: None,
                issue,
            });
        }
        out
    }
    fn field_marshals(&self, b: &[u8]) -> Vec<FieldMarshal> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (_, _, blob) = self.indexes();
        let parent_width = coded_width(t, 1, &[4, 8]);
        let mut at = table_start(t, 13);
        let mut out = Vec::new();

        for row in 1..=t.rows[13] {
            let source_offset = Some(at);
            let parent = read_index(b, &mut at, parent_width).ok();
            let blob_offset = read_index(b, &mut at, blob).ok();
            let blob_bytes = blob_offset.and_then(|offset| blob_value(&self.blobs, offset));
            let decoded_native_type = blob_bytes.as_deref().and_then(decode_native_type);
            let issue = if parent.is_none() || blob_offset.is_none() {
                Some("truncated FieldMarshal row".to_owned())
            } else if parent == Some(0) {
                Some("FieldMarshal parent coded index is null".to_owned())
            } else if parent.is_some_and(|value| value & 1 >= 2) {
                Some("FieldMarshal parent coded index has an invalid tag".to_owned())
            } else if parent.is_some_and(|value| {
                let table = [4usize, 8][value & 1];
                let row = value >> 1;
                row == 0 || row > t.rows[table] as usize
            }) {
                Some("FieldMarshal parent reference is out of range".to_owned())
            } else if blob_offset != Some(0) && blob_bytes.is_none() {
                Some("FieldMarshal native type blob is outside #Blob".to_owned())
            } else if blob_bytes.as_deref().map_or(true, |value| value.is_empty()) {
                Some("FieldMarshal native type blob is empty".to_owned())
            } else if decoded_native_type.is_none() {
                Some("FieldMarshal native type is unsupported or malformed".to_owned())
            } else {
                None
            };

            out.push(FieldMarshal {
                token: token(13, row),
                source_offset,
                parent_token: parent
                    .filter(|value| *value != 0)
                    .map(|value| coded_token(value, 1, &[4, 8])),
                native_type_blob_offset: blob_offset.unwrap_or(0),
                native_type_blob_hex: blob_bytes.as_deref().map(hex),
                decoded_native_type,
                issue,
            });
        }

        out
    }
    fn decl_security(&self, b: &[u8]) -> Vec<DeclSecurity> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (_, _, blob) = self.indexes();
        let parent_width = coded_width(t, 2, &[2, 6, 32]);
        let mut at = table_start(t, 14);
        let mut out = Vec::new();

        for row in 1..=t.rows[14] {
            let source_offset = Some(at);
            let action = u16(b, at).ok();
            at += 2;
            let parent = read_index(b, &mut at, parent_width).ok();
            let permission_blob_offset = read_index(b, &mut at, blob).ok();
            let permission_blob =
                permission_blob_offset.and_then(|offset| blob_value(&self.blobs, offset));
            let issue = if action.is_none() || parent.is_none() || permission_blob_offset.is_none()
            {
                Some("truncated DeclSecurity row".to_owned())
            } else if parent == Some(0) {
                Some("DeclSecurity parent coded index is null".to_owned())
            } else if parent.is_some_and(|value| value & 3 >= 3) {
                Some("DeclSecurity parent coded index has an invalid tag".to_owned())
            } else if parent.is_some_and(|value| {
                let table = [2usize, 6, 32][value & 3];
                let row = value >> 2;
                row == 0 || row > t.rows[table] as usize
            }) {
                Some("DeclSecurity parent reference is out of range".to_owned())
            } else if permission_blob_offset != Some(0) && permission_blob.is_none() {
                Some("DeclSecurity permission blob is outside #Blob".to_owned())
            } else if permission_blob
                .as_deref()
                .map_or(true, |value| value.is_empty())
            {
                Some("DeclSecurity permission blob is empty".to_owned())
            } else {
                None
            };
            out.push(DeclSecurity {
                token: token(14, row),
                source_offset,
                action,
                parent_token: parent
                    .filter(|value| *value != 0)
                    .map(|value| coded_token(value, 2, &[2, 6, 32])),
                permission_blob_offset: permission_blob_offset.unwrap_or(0),
                permission_blob_hex: permission_blob.as_deref().map(hex),
                issue,
            });
        }

        out
    }
    fn class_layouts(&self, b: &[u8]) -> Vec<ClassLayout> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[15] == 0 {
            return Vec::new();
        }

        let parent_width = table_index_width(t, 2);
        let mut at = table_start(t, 15);
        let mut out = Vec::new();

        for row in 1..=t.rows[15] {
            let source_offset = Some(at);
            let packing_size = u16(b, at).ok();
            at += 2;
            let class_size = u32(b, at).ok();
            at += 4;
            let parent = read_index(b, &mut at, parent_width).ok();

            let issue = if packing_size.is_none() || class_size.is_none() || parent.is_none() {
                Some("truncated ClassLayout row".to_owned())
            } else if parent == Some(0) || parent.is_some_and(|value| value > t.rows[2] as usize) {
                Some("ClassLayout parent type reference is out of range".to_owned())
            } else if packing_size
                .is_some_and(|value| value != 0 && !(value.is_power_of_two() && value <= 128))
            {
                Some("ClassLayout packing size is invalid".to_owned())
            } else {
                None
            };

            out.push(ClassLayout {
                token: token(15, row),
                source_offset,
                packing_size,
                class_size,
                parent_type_token: parent
                    .filter(|value| *value != 0)
                    .map(|value| token(2, value as u32)),
                issue,
            });
        }

        out
    }
    fn assembly_processors(&self, b: &[u8]) -> Vec<AssemblyProcessor> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[33] == 0 {
            return Vec::new();
        }

        let mut at = table_start(t, 33);
        let mut out = Vec::new();
        for row in 1..=t.rows[33] {
            let source_offset = Some(at);
            let processor = u32(b, at).ok();
            at += 4;
            let issue = processor
                .is_none()
                .then(|| "truncated AssemblyProcessor row".to_owned());
            out.push(AssemblyProcessor {
                token: token(33, row),
                source_offset,
                processor,
                issue,
            });
        }
        out
    }
    fn assembly_os(&self, b: &[u8]) -> Vec<AssemblyOs> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[34] == 0 {
            return Vec::new();
        }

        let mut at = table_start(t, 34);
        let mut out = Vec::new();
        for row in 1..=t.rows[34] {
            let source_offset = Some(at);
            let platform_id = u32(b, at).ok();
            at += 4;
            let major_version = u32(b, at).ok();
            at += 4;
            let minor_version = u32(b, at).ok();
            at += 4;
            let issue =
                (platform_id.is_none() || major_version.is_none() || minor_version.is_none())
                    .then(|| "truncated AssemblyOS row".to_owned());
            out.push(AssemblyOs {
                token: token(34, row),
                source_offset,
                platform_id,
                major_version,
                minor_version,
                issue,
            });
        }
        out
    }
    fn assembly_ref_processors(&self, b: &[u8]) -> Vec<AssemblyRefProcessor> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[36] == 0 {
            return Vec::new();
        }

        let assembly_ref_width = table_index_width(t, 35);
        let mut at = table_start(t, 36);
        let mut out = Vec::new();
        for row in 1..=t.rows[36] {
            let source_offset = Some(at);
            let processor = u32(b, at).ok();
            at += 4;
            let assembly_ref = read_index(b, &mut at, assembly_ref_width).ok();
            let issue = if processor.is_none() || assembly_ref.is_none() {
                Some("truncated AssemblyRefProcessor row".to_owned())
            } else if assembly_ref == Some(0)
                || assembly_ref.is_some_and(|value| value > t.rows[35] as usize)
            {
                Some("AssemblyRefProcessor assembly reference is out of range".to_owned())
            } else {
                None
            };
            out.push(AssemblyRefProcessor {
                token: token(36, row),
                source_offset,
                processor,
                assembly_ref_token: assembly_ref
                    .filter(|value| *value != 0 && *value <= t.rows[35] as usize)
                    .map(|value| token(35, value as u32)),
                issue,
            });
        }
        out
    }
    fn assembly_ref_os(&self, b: &[u8]) -> Vec<AssemblyRefOs> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[37] == 0 {
            return Vec::new();
        }

        let assembly_ref_width = table_index_width(t, 35);
        let mut at = table_start(t, 37);
        let mut out = Vec::new();
        for row in 1..=t.rows[37] {
            let source_offset = Some(at);
            let platform_id = u32(b, at).ok();
            at += 4;
            let major_version = u32(b, at).ok();
            at += 4;
            let minor_version = u32(b, at).ok();
            at += 4;
            let assembly_ref = read_index(b, &mut at, assembly_ref_width).ok();
            let issue = if platform_id.is_none()
                || major_version.is_none()
                || minor_version.is_none()
                || assembly_ref.is_none()
            {
                Some("truncated AssemblyRefOS row".to_owned())
            } else if assembly_ref == Some(0)
                || assembly_ref.is_some_and(|value| value > t.rows[35] as usize)
            {
                Some("AssemblyRefOS assembly reference is out of range".to_owned())
            } else {
                None
            };
            out.push(AssemblyRefOs {
                token: token(37, row),
                source_offset,
                platform_id,
                major_version,
                minor_version,
                assembly_ref_token: assembly_ref
                    .filter(|value| *value != 0 && *value <= t.rows[35] as usize)
                    .map(|value| token(35, value as u32)),
                issue,
            });
        }
        out
    }
    fn files(&self, b: &[u8]) -> Vec<ManagedFile> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        if t.rows[38] == 0 {
            return Vec::new();
        }

        let (strings, _, blob) = self.indexes();
        let mut at = table_start(t, 38);
        let mut out = Vec::new();
        for row in 1..=t.rows[38] {
            let source_offset = Some(at);
            let flags = u32(b, at).ok();
            at += 4;
            let name_offset = read_index(b, &mut at, strings).ok();
            let hash_blob_offset = read_index(b, &mut at, blob).ok();
            let name = name_offset.map(|value| self.strings(value));
            let hash_blob = hash_blob_offset.and_then(|value| blob_value(&self.blobs, value));
            let issue = if flags.is_none() || name_offset.is_none() || hash_blob_offset.is_none() {
                Some("truncated File row".to_owned())
            } else if name_offset != Some(0)
                && name_offset.is_some_and(|value| value >= self.strings.len())
            {
                Some("File name is outside #Strings".to_owned())
            } else if hash_blob_offset != Some(0) && hash_blob.is_none() {
                Some("File hash blob is outside #Blob".to_owned())
            } else {
                None
            };
            out.push(ManagedFile {
                token: token(38, row),
                source_offset,
                flags,
                contains_metadata: flags.map(|value| value & 1 != 0),
                name_offset,
                name,
                hash_blob_offset,
                hash_blob_hex: hash_blob.as_deref().map(hex),
                hash_blob_sha256: hash_blob.as_deref().map(digest),
                issue,
            });
        }
        out
    }
    fn generic_params(&self, b: &[u8]) -> Vec<GenericParameter> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (s, _, _) = self.indexes();
        let owner = coded_width(t, 1, &[2, 6]);
        let mut at = table_start(t, 42);
        let mut out = Vec::new();
        for row in 1..=t.rows[42] {
            let source_offset = Some(at);
            let number = u16(b, at).unwrap_or(0);
            let flags = u16(b, at + 2).unwrap_or(0);
            at += 4;
            let owner_value = read_index(b, &mut at, owner).unwrap_or(0);
            let name = read_index(b, &mut at, s).unwrap_or(0);
            let variance = match flags & 0x0003 {
                0x0001 => Some("covariant"),
                0x0002 => Some("contravariant"),
                _ => None,
            };
            let mut special_constraints = Vec::new();
            if flags & 0x0004 != 0 {
                special_constraints.push("reference-type");
            }
            if flags & 0x0008 != 0 {
                special_constraints.push("non-nullable-value-type");
            }
            if flags & 0x0010 != 0 {
                special_constraints.push("default-constructor");
            }
            let owner_table = [2usize, 6][owner_value & 1];
            let owner_row = owner_value >> 1;
            let owner_issue = if owner_value == 0 {
                Some("GenericParam owner index is zero".to_owned())
            } else if owner_row > t.rows[owner_table] as usize {
                Some("GenericParam owner token is outside its table".to_owned())
            } else {
                None
            };
            out.push(GenericParameter {
                token: token(42, row),
                source_offset,
                number,
                flags,
                owner_token: coded_token(owner_value, 1, &[2, 6]),
                name: self.strings(name),
                variance,
                special_constraints,
                unknown_flags: flags & !0x001f,
                issue: owner_issue,
            });
        }
        out
    }
    fn generic_constraints(&self, b: &[u8]) -> Vec<GenericParameterConstraint> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let owner = table_index_width(t, 42);
        let constraint = coded_width(t, 2, &[1, 2, 27]);
        let mut at = table_start(t, 44);
        let mut out = Vec::new();
        for row in 1..=t.rows[44] {
            let source_offset = Some(at);
            let o = read_index(b, &mut at, owner).unwrap_or(0);
            let c = read_index(b, &mut at, constraint).unwrap_or(0);
            out.push(GenericParameterConstraint {
                token: token(44, row),
                source_offset,
                owner_token: token(42, o as u32),
                constraint_token: coded_token(c, 2, &[1, 2, 27]),
                constraint_kind: match c & 3 {
                    0 => "type-ref",
                    1 => "type-def",
                    2 => "type-spec",
                    _ => "unknown",
                },
                issue: if o == 0 || o > t.rows[42] as usize {
                    Some("GenericParamConstraint owner is out of range".to_owned())
                } else if c & 3 >= 3 {
                    Some("GenericParamConstraint type coded tag is invalid".to_owned())
                } else {
                    let table = [1usize, 2, 27][c & 3];
                    let row = c >> 2;
                    (row == 0 || row > t.rows[table] as usize)
                        .then_some("GenericParamConstraint type is out of range".to_owned())
                },
            });
        }
        out
    }
    fn type_specs(&self, b: &[u8]) -> Vec<TypeSpecification> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (_, _, blob) = self.indexes();
        let mut at = table_start(t, 27);
        let mut out = Vec::new();
        for row in 1..=t.rows[27] {
            let sig = read_index(b, &mut at, blob).unwrap_or(0);
            out.push(TypeSpecification {
                token: token(27, row),
                signature: self.signature(sig, "type-spec"),
            });
        }
        out
    }
    fn method_specs(&self, b: &[u8]) -> Vec<MethodSpecification> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (_, _, blob) = self.indexes();
        let method = coded_width(t, 1, &[6, 10]);
        let mut at = table_start(t, 43);
        let mut out = Vec::new();
        for row in 1..=t.rows[43] {
            let source_offset = Some(at);
            let m = read_index(b, &mut at, method).unwrap_or(0);
            let sig = read_index(b, &mut at, blob).unwrap_or(0);
            out.push(MethodSpecification {
                token: token(43, row),
                source_offset,
                method_token: coded_token(m, 1, &[6, 10]),
                instantiation: self.signature(sig, "method-spec"),
                issue: {
                    let table = [6usize, 10][m & 1];
                    let method_row = m >> 1;
                    (method_row == 0 || method_row > t.rows[table] as usize)
                        .then_some("MethodSpec method is out of range".to_owned())
                },
            });
        }
        out
    }
    fn standalone_signatures(&self, b: &[u8]) -> Vec<StandaloneSignature> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (_, _, blob) = self.indexes();
        let mut at = table_start(t, 17);
        let mut out = Vec::new();
        for row in 1..=t.rows[17] {
            let source_offset = Some(at);
            let index = read_index(b, &mut at, blob).ok();
            let issue = index
                .filter(|value| *value != 0)
                .and_then(|value| blob_value(&self.blobs, value))
                .is_none()
                .then_some("StandAloneSig blob is empty or out of bounds".to_owned());
            out.push(StandaloneSignature {
                token: token(17, row),
                source_offset,
                signature: self.signature(index.unwrap_or(0), "local"),
                issue,
            });
        }
        out
    }
    fn constants(&self, b: &[u8]) -> Vec<Constant> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (_, _, blob) = self.indexes();
        let parent_width = coded_width(t, 2, &[4, 8, 23]);
        let mut at = table_start(t, 11);
        let mut out = Vec::new();
        for row in 1..=t.rows[11] {
            let source_offset = Some(at);
            let element_type = b.get(at).copied().unwrap_or(0);
            at = at.saturating_add(4);
            let parent = read_index(b, &mut at, parent_width).ok();
            let value_offset = read_index(b, &mut at, blob).ok();
            let value = value_offset.and_then(|offset| blob_value(&self.blobs, offset));
            let issue = if parent.is_none() || value_offset.is_none() {
                Some("truncated Constant row".to_owned())
            } else if value_offset != Some(0) && value.is_none() {
                Some("Constant value blob is outside #Blob".to_owned())
            } else {
                None
            };
            out.push(Constant {
                token: token(11, row),
                parent_token: parent
                    .filter(|value| *value != 0)
                    .map(|value| coded_token(value, 2, &[4, 8, 23])),
                element_type,
                source_offset,
                value_offset,
                value_hex: value.as_deref().map(hex),
                decoded_value: value
                    .as_deref()
                    .and_then(|bytes| decode_constant(element_type, bytes)),
                issue,
            });
        }
        out
    }
    fn interface_impls(&self, b: &[u8]) -> Vec<InterfaceImplementation> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let class_width = table_index_width(t, 2);
        let interface_width = coded_width(t, 2, &[1, 2, 27]);
        let mut at = table_start(t, 9);
        let mut out = Vec::new();
        for row in 1..=t.rows[9] {
            let source_offset = Some(at);
            let class = read_index(b, &mut at, class_width).ok();
            let interface = read_index(b, &mut at, interface_width).ok();
            let issue = validate_interface_impl(class, interface, t).or_else(|| {
                (class.is_none() || interface.is_none())
                    .then_some("truncated InterfaceImpl row".to_owned())
            });
            out.push(InterfaceImplementation {
                token: token(9, row),
                source_offset,
                declaring_type_token: class
                    .filter(|value| *value != 0)
                    .map(|value| token(2, value as u32)),
                interface_token: interface
                    .filter(|value| *value != 0)
                    .map(|value| coded_token(value, 2, &[1, 2, 27])),
                raw_interface_index: interface,
                issue,
            });
        }
        out
    }
    fn nested_classes(&self, b: &[u8]) -> Vec<NestedClass> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let width = table_index_width(t, 2);
        let mut at = table_start(t, 41);
        let mut out = Vec::new();
        for row in 1..=t.rows[41] {
            let source_offset = Some(at);
            let nested = read_index(b, &mut at, width).ok();
            let enclosing = read_index(b, &mut at, width).ok();
            let issue = if nested.is_none() || enclosing.is_none() {
                Some("truncated NestedClass row".to_owned())
            } else if nested == Some(0)
                || enclosing == Some(0)
                || nested.is_some_and(|value| value > t.rows[2] as usize)
                || enclosing.is_some_and(|value| value > t.rows[2] as usize)
            {
                Some("NestedClass TypeDef reference is out of range".to_owned())
            } else {
                None
            };
            out.push(NestedClass {
                token: token(41, row),
                source_offset,
                nested_type_token: nested.map(|value| token(2, value as u32)),
                enclosing_type_token: enclosing.map(|value| token(2, value as u32)),
                issue,
            });
        }
        out
    }
    fn custom_attributes(&self, b: &[u8]) -> Vec<CustomAttribute> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (_, _, blob) = self.indexes();
        let parent_width = coded_width(
            t,
            5,
            &[
                0, 1, 2, 4, 6, 8, 9, 10, 12, 14, 17, 20, 23, 26, 27, 32, 35, 38, 39, 40, 42, 43, 44,
            ],
        );
        let constructor_width = coded_width(t, 3, &[6, 10]);
        let mut at = table_start(t, 12);
        let mut out = Vec::new();
        for row in 1..=t.rows[12] {
            let source_offset = Some(at);
            let parent = read_index(b, &mut at, parent_width).ok();
            let constructor = read_index(b, &mut at, constructor_width).ok();
            let blob_offset = read_index(b, &mut at, blob).ok();
            let blob_bytes = blob_offset.and_then(|offset| blob_value(&self.blobs, offset));
            let (serialized_prolog, serialized_named_argument_count, serialized_shape_issue) =
                blob_bytes
                    .as_deref()
                    .map(decode_attribute_shape)
                    .unwrap_or((None, None, None));
            let issue = if parent.is_none() || constructor.is_none() || blob_offset.is_none() {
                Some("truncated CustomAttribute row".to_owned())
            } else if blob_offset != Some(0) && blob_bytes.is_none() {
                Some("CustomAttribute blob index is outside #Blob".to_owned())
            } else if let Some(value) = parent.filter(|value| *value == 0) {
                Some(format!(
                    "CustomAttribute parent coded index 0x{value:x} is null"
                ))
            } else if let Some(value) = constructor.filter(|value| *value == 0) {
                Some(format!(
                    "CustomAttribute constructor coded index 0x{value:x} is null"
                ))
            } else if constructor.is_some_and(|value| !matches!(value & 0x7, 2 | 3)) {
                Some("CustomAttribute constructor coded index has an invalid tag".to_owned())
            } else {
                None
            };
            out.push(CustomAttribute {
                token: token(12, row),
                source_offset,
                parent_token: parent
                    .filter(|value| *value != 0)
                    .map(custom_attribute_parent_token),
                constructor_token: constructor
                    .filter(|value| *value != 0)
                    .map(custom_attribute_constructor_token),
                blob_offset: blob_offset.unwrap_or(0),
                blob_hex: blob_bytes.as_deref().map(hex),
                value_length: blob_bytes.as_ref().map_or(0, Vec::len),
                value_sha256: blob_bytes.as_deref().map_or_else(|| digest(&[]), digest),
                decoded_fixed_string: blob_bytes.as_deref().and_then(decode_attribute_string),
                serialized_prolog,
                serialized_named_argument_count,
                serialized_shape_issue,
                issue,
            });
        }
        out
    }
    fn manifest_resources(
        &self,
        b: &[u8],
        resource_bytes: Option<&[u8]>,
        resource_base: Option<usize>,
    ) -> Vec<ManifestResource> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (strings, _, _) = self.indexes();
        let implementation_width = coded_width(t, 2, &[38, 35, 39]);
        let mut at = table_start(t, 40);
        let mut out = Vec::new();
        for row in 1..=t.rows[40] {
            let row_source_offset = Some(at);
            let offset = u32(b, at).ok();
            let flags = u32(b, at + 4).unwrap_or(0);
            at += 8;
            let name_index = read_index(b, &mut at, strings).ok();
            let implementation = read_index(b, &mut at, implementation_width).ok();
            let mut issue = if offset.is_none() || name_index.is_none() || implementation.is_none()
            {
                Some("truncated ManifestResource row".to_owned())
            } else {
                None
            };
            if issue.is_none() {
                if let Some(value) = implementation.filter(|value| *value != 0) {
                    let table = [38usize, 35, 39][value & 3];
                    let target_row = value >> 2;
                    if target_row == 0 || target_row > t.rows[table] as usize {
                        issue = Some(
                            "ManifestResource implementation target is out of range".to_owned(),
                        );
                    }
                }
            }
            let implementation_token = implementation
                .filter(|value| *value != 0)
                .map(|value| coded_token(value, 2, &[38, 35, 39]));
            let mut source_offset = None;
            let mut size = None;
            let mut bytes_hex = None;
            let mut data_sha256 = None;
            if implementation.is_none() || implementation == Some(0) {
                if let Some(resource_offset) = offset {
                    if let Some(data) = resource_bytes {
                        let start = resource_offset as usize;
                        match data.get(start..start.saturating_add(4)) {
                            Some(length_bytes) => {
                                let declared =
                                    u32::from_le_bytes(length_bytes.try_into().unwrap()) as usize;
                                let available = data.len().saturating_sub(start + 4);
                                let actual = declared.min(available);
                                let bounded = actual.min(MAX_EMBEDDED_RESOURCE_BYTES);
                                source_offset = resource_base.map(|base| base + start + 4);
                                size = Some(actual);
                                bytes_hex = data.get(start + 4..start + 4 + bounded).map(hex);
                                data_sha256 = data.get(start + 4..start + 4 + actual).map(digest);
                                if actual != declared {
                                    issue =
                                        Some("embedded resource payload is truncated".to_owned());
                                } else if bounded != actual {
                                    issue = Some(
                                        "embedded resource payload exceeds inspection budget"
                                            .to_owned(),
                                    );
                                }
                            }
                            None => {
                                issue =
                                    Some("manifest resource offset is outside resources".to_owned())
                            }
                        }
                    } else {
                        issue = Some("CLI resources directory is unavailable".to_owned());
                    }
                }
            }
            out.push(ManifestResource {
                token: token(40, row),
                row_source_offset,
                name: name_index
                    .map(|value| self.strings(value))
                    .unwrap_or_default(),
                flags,
                visibility: match flags & 7 {
                    1 => "public",
                    2 => "private",
                    _ => "unknown",
                },
                embedded: implementation.is_none() || implementation == Some(0),
                implementation_kind: match implementation {
                    None | Some(0) => "embedded",
                    Some(value) if value & 3 == 0 => "file",
                    Some(value) if value & 3 == 1 => "assembly-ref",
                    Some(value) if value & 3 == 2 => "exported-type",
                    Some(_) => "unknown",
                },
                implementation_token,
                manifest_offset: offset.unwrap_or(0),
                source_offset,
                size,
                bytes_hex,
                data_sha256,
                issue,
            });
        }
        out
    }
    fn exported_types(&self, b: &[u8]) -> Vec<ExportedType> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };

        let strings = self.indexes().0;
        let implementation_width = coded_width(t, 2, &[38, 35, 39]);
        let mut at = table_start(t, 39);
        let mut out = Vec::new();

        for row in 1..=t.rows[39] {
            let row_offset = Some(at);
            let flags = u32(b, at).ok();
            let type_def_id = u32(b, at + 4).ok();
            at += 8;
            let name_index = read_index(b, &mut at, strings).ok();
            let namespace_index = read_index(b, &mut at, strings).ok();
            let implementation = read_index(b, &mut at, implementation_width).ok();

            let mut issue = if flags.is_none()
                || type_def_id.is_none()
                || name_index.is_none()
                || namespace_index.is_none()
                || implementation.is_none()
            {
                Some("truncated ExportedType row".to_owned())
            } else {
                None
            };

            if issue.is_none() {
                match implementation {
                    Some(0) | None => {
                        issue = Some(
                            "ExportedType implementation coded index is null; a target row is required"
                                .to_owned(),
                        );
                    }
                    Some(value) => {
                        let target_row = value >> 2;
                        match [38usize, 35, 39].get(value & 3) {
                            Some(table)
                                if target_row != 0 && target_row <= t.rows[*table] as usize => {}
                            Some(_) => {
                                issue = Some(
                                    "ExportedType implementation target is out of range".to_owned(),
                                );
                            }
                            None => {
                                issue = Some(
                                    "ExportedType implementation coded index has an invalid tag"
                                        .to_owned(),
                                );
                            }
                        }
                    }
                }
            }

            out.push(ExportedType {
                token: token(39, row),
                row_offset,
                namespace: namespace_index
                    .map(|value| self.strings(value))
                    .unwrap_or_default(),
                name: name_index
                    .map(|value| self.strings(value))
                    .unwrap_or_default(),
                flags: flags.unwrap_or(0),
                forwarder: flags.is_some_and(|value| value & 0x0020_0000 != 0),
                type_def_id: type_def_id.unwrap_or(0),
                implementation_kind: match implementation {
                    None | Some(0) => "embedded",
                    Some(value) if value & 3 == 0 => "file",
                    Some(value) if value & 3 == 1 => "assembly-ref",
                    Some(value) if value & 3 == 2 => "exported-type",
                    Some(_) => "unknown",
                },
                implementation_token: implementation
                    .filter(|value| *value != 0 && (*value & 3) < 3)
                    .map(|value| coded_token(value, 2, &[38, 35, 39])),
                issue,
            });
        }

        out
    }
    fn method_impls(&self, b: &[u8]) -> Vec<MethodImplementation> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let class_width = table_index_width(t, 2);
        let method_width = coded_width(t, 1, &[6, 10]);
        let mut at = table_start(t, 25);
        let mut out = Vec::new();
        for row in 1..=t.rows[25] {
            let source_offset = Some(at);
            let class = read_index(b, &mut at, class_width).ok();
            let body = read_index(b, &mut at, method_width).ok();
            let declaration = read_index(b, &mut at, method_width).ok();
            let issue = validate_method_impl(class, body, declaration, t).or_else(|| {
                (class.is_none() || body.is_none() || declaration.is_none())
                    .then_some("truncated MethodImpl row".to_owned())
            });
            out.push(MethodImplementation {
                token: token(25, row),
                source_offset,
                declaring_type_token: class
                    .filter(|value| *value != 0)
                    .map(|value| token(2, value as u32)),
                body_method_token: body
                    .filter(|value| *value != 0)
                    .map(|value| coded_token(value, 1, &[6, 10])),
                declaration_method_token: declaration
                    .filter(|value| *value != 0)
                    .map(|value| coded_token(value, 1, &[6, 10])),
                raw_body_index: body,
                raw_declaration_index: declaration,
                issue,
            });
        }
        out
    }
    fn property_maps(&self, b: &[u8]) -> Vec<PropertyMap> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let mut at = table_start(t, 21);
        let mut out = Vec::new();
        for row in 1..=t.rows[21] {
            let source_offset = Some(at);
            let p = read_index(b, &mut at, table_index_width(t, 2)).unwrap_or(0);
            let l = read_index(b, &mut at, table_index_width(t, 23)).unwrap_or(0);
            out.push(PropertyMap {
                token: token(21, row),
                source_offset,
                parent_type_token: token(2, p as u32),
                property_list: l as u32,
            });
        }
        out
    }
    fn properties(&self, b: &[u8]) -> Vec<PropertyDefinition> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (s, _, blob) = self.indexes();
        let mut at = table_start(t, 23);
        let mut out = Vec::new();
        for row in 1..=t.rows[23] {
            let source_offset = Some(at);
            let f = u16(b, at).unwrap_or(0);
            at += 2;
            let n = read_index(b, &mut at, s).unwrap_or(0);
            let sig = read_index(b, &mut at, blob).unwrap_or(0);
            out.push(PropertyDefinition {
                token: token(23, row),
                source_offset,
                declaring_type_token: None,
                getter_method_token: None,
                setter_method_token: None,
                other_method_tokens: Vec::new(),
                flags: f,
                name: self.strings(n),
                signature: self.signature(sig, "property"),
                custom_attributes: Vec::new(),
                constants: Vec::new(),
            });
        }
        out
    }
    fn method_semantics(&self, b: &[u8]) -> Vec<MethodSemantic> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let mut at = table_start(t, 24);
        let mut out = Vec::new();
        for row in 1..=t.rows[24] {
            let source_offset = Some(at);
            let s = u16(b, at).ok();
            at += 2;
            let m = read_index(b, &mut at, table_index_width(t, 6)).ok();
            let a = read_index(b, &mut at, coded_width(t, 1, &[20, 23])).ok();
            let (flag_names, unknown_flags) = decode_method_semantics_flags(s.unwrap_or(0));
            let issue = if s.is_none() || m.is_none() || a.is_none() {
                Some("truncated MethodSemantics row".to_owned())
            } else if m == Some(0) || m.is_some_and(|value| value > t.rows[6] as usize) {
                Some("MethodSemantics method reference is out of range".to_owned())
            } else if a == Some(0) {
                Some("MethodSemantics association is null".to_owned())
            } else if a.is_some_and(|value| {
                let table = [20usize, 23][value & 1];
                let row = value >> 1;
                row == 0 || row > t.rows[table] as usize
            }) {
                Some("MethodSemantics association is out of range".to_owned())
            } else {
                None
            };
            out.push(MethodSemantic {
                token: token(24, row),
                source_offset,
                semantics: s.unwrap_or(0),
                flag_names,
                unknown_flags,
                method_token: token(6, m.unwrap_or(0) as u32),
                association_token: coded_token(a.unwrap_or(0), 1, &[20, 23]),
                association_kind: match a.map(|value| value & 1) {
                    Some(0) => "event",
                    Some(1) => "property",
                    _ => "unknown",
                },
                issue,
            });
        }
        out
    }
    fn event_maps(&self, b: &[u8]) -> Vec<EventMap> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let mut at = table_start(t, 18);
        let mut out = Vec::new();
        for row in 1..=t.rows[18] {
            let source_offset = Some(at);
            let p = read_index(b, &mut at, table_index_width(t, 2)).unwrap_or(0);
            let e = read_index(b, &mut at, table_index_width(t, 20)).unwrap_or(0);
            out.push(EventMap {
                token: token(18, row),
                source_offset,
                parent_type_token: token(2, p as u32),
                event_list: e as u32,
            });
        }
        out
    }
    fn events(&self, b: &[u8]) -> Vec<EventDefinition> {
        let Some(t) = &self.tables else {
            return Vec::new();
        };
        let (s, _, _) = self.indexes();
        let mut at = table_start(t, 20);
        let mut out = Vec::new();
        for row in 1..=t.rows[20] {
            let source_offset = Some(at);
            let f = u16(b, at).unwrap_or(0);
            at += 2;
            let n = read_index(b, &mut at, s).unwrap_or(0);
            let ty = read_index(b, &mut at, coded_width(t, 2, &[1, 2, 27])).unwrap_or(0);
            out.push(EventDefinition {
                token: token(20, row),
                source_offset,
                declaring_type_token: None,
                add_method_token: None,
                remove_method_token: None,
                raise_method_token: None,
                other_method_tokens: Vec::new(),
                flags: f,
                name: self.strings(n),
                event_type_token: format!("0x{ty:08x}"),
                custom_attributes: Vec::new(),
            });
        }
        out
    }
}

fn project_type_relationships(
    types: &mut [TypeDefinition],
    interface_impls: &[InterfaceImplementation],
    method_impls: &[MethodImplementation],
) {
    for relationship in interface_impls {
        let Some((_, row)) = relationship
            .declaring_type_token
            .as_deref()
            .and_then(decode_token)
        else {
            continue;
        };
        if let Some(owner) = types.get_mut(row.saturating_sub(1) as usize) {
            owner.interface_impl_tokens.push(relationship.token.clone());
        }
    }
    for relationship in method_impls {
        let Some((_, row)) = relationship
            .declaring_type_token
            .as_deref()
            .and_then(decode_token)
        else {
            continue;
        };
        if let Some(owner) = types.get_mut(row.saturating_sub(1) as usize) {
            owner.method_impl_tokens.push(relationship.token.clone());
        }
    }
}

fn project_nested_classes(types: &mut [TypeDefinition], nested_classes: &[NestedClass]) {
    for relationship in nested_classes {
        let Some(nested_token) = relationship.nested_type_token.as_deref() else {
            continue;
        };
        let Some(enclosing_token) = relationship.enclosing_type_token.as_deref() else {
            continue;
        };
        let Some((nested_table, nested_row)) = decode_token(nested_token) else {
            continue;
        };
        let Some((enclosing_table, enclosing_row)) = decode_token(enclosing_token) else {
            continue;
        };
        if nested_table != 2 || enclosing_table != 2 {
            continue;
        }

        let Some(nested_type) = types.get_mut(nested_row.saturating_sub(1) as usize) else {
            continue;
        };
        nested_type.enclosing_type_token = Some(enclosing_token.to_owned());

        let Some(enclosing_type) = types.get_mut(enclosing_row.saturating_sub(1) as usize) else {
            continue;
        };
        enclosing_type
            .nested_type_tokens
            .push(nested_token.to_owned());
    }
}

fn project_type_full_names(types: &mut [TypeDefinition]) {
    for index in 0..types.len() {
        types[index].full_name = type_name_from_index(types, index);
    }
}

fn project_type_name_digests(types: &mut [TypeDefinition]) {
    let mut computed = vec![false; types.len()];
    let mut digests = vec![None; types.len()];
    let mut visiting = vec![false; types.len()];

    for index in 0..types.len() {
        digests[index] =
            type_name_digest_from_index(types, index, &mut computed, &mut digests, &mut visiting);
        types[index].name_sha256 = digests[index].clone();
    }
}

fn type_name_digest_from_index(
    types: &[TypeDefinition],
    index: usize,
    computed: &mut [bool],
    digests: &mut [Option<String>],
    visiting: &mut [bool],
) -> Option<String> {
    if computed[index] {
        return digests[index].clone();
    }
    if visiting[index] {
        return None;
    }

    visiting[index] = true;
    let type_definition = &types[index];
    let enclosing_index = type_definition
        .enclosing_type_token
        .as_deref()
        .and_then(|token| types.iter().position(|candidate| candidate.token == token));
    let enclosing_digest = enclosing_index
        .and_then(|parent| type_name_digest_from_index(types, parent, computed, digests, visiting));

    let digest = if type_definition.enclosing_type_token.is_some() {
        enclosing_digest.map(|parent_digest| {
            let mut hasher = Sha256::new();
            hasher.update([1]);
            hasher.update(hex_digest_bytes(&parent_digest));
            hasher.update(type_definition.namespace.as_bytes());
            hasher.update([0]);
            hasher.update(type_definition.name.as_bytes());
            format!("{:x}", hasher.finalize())
        })
    } else {
        let mut hasher = Sha256::new();
        hasher.update([0]);
        hasher.update(type_definition.namespace.as_bytes());
        hasher.update([0]);
        hasher.update(type_definition.name.as_bytes());
        Some(format!("{:x}", hasher.finalize()))
    };

    visiting[index] = false;
    computed[index] = true;
    digests[index] = digest.clone();
    digest
}

fn hex_digest_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap_or(0);
            let low = (pair[1] as char).to_digit(16).unwrap_or(0);
            ((high << 4) | low) as u8
        })
        .collect()
}

fn type_name_from_index(types: &[TypeDefinition], index: usize) -> String {
    let mut parts = Vec::new();
    let mut current = Some(index);
    let mut visited = std::collections::BTreeSet::new();
    while let Some(current_index) = current {
        if !visited.insert(current_index) {
            return String::new();
        }
        let ty = &types[current_index];
        parts.push(ty.name.clone());
        current = ty
            .enclosing_type_token
            .as_deref()
            .and_then(|token| types.iter().position(|candidate| candidate.token == token));
    }
    parts.reverse();
    let name = parts.join(".");
    let ty = &types[index];
    if ty.enclosing_type_token.is_some() {
        return name;
    }
    if ty.namespace.is_empty() {
        name
    } else {
        format!("{}.{}", ty.namespace, name)
    }
}

fn project_field_rvas(fields: &mut [FieldDefinition], field_rvas: &[FieldRva]) {
    for field_rva in field_rvas {
        let Some((_, row)) = field_rva.field_token.as_deref().and_then(decode_token) else {
            continue;
        };
        let Some(field) = fields.get_mut(row.saturating_sub(1) as usize) else {
            continue;
        };
        field.rva = field_rva.rva;
        field.data_offset = field_rva.data_offset;
        field.data_hex = field_rva.data_hex.clone();
        field.issue = field_rva.issue.clone();
    }
}

fn project_field_layouts(fields: &mut [FieldDefinition], layouts: &[FieldLayout]) {
    for layout in layouts {
        let Some((_, row)) = layout.field_token.as_deref().and_then(decode_token) else {
            continue;
        };
        let Some(field) = fields.get_mut(row.saturating_sub(1) as usize) else {
            continue;
        };
        field.layout_offset = layout.offset;
        if field.issue.is_none() {
            field.issue = layout.issue.clone();
        }
    }
}

fn project_impl_maps(methods: &mut [MethodDefinition], impl_maps: &[ImplMap]) {
    for mapping in impl_maps {
        let Some(member_token) = mapping.member_token.as_deref() else {
            continue;
        };
        let Some((table, row)) = decode_token(member_token) else {
            continue;
        };
        if table != 6 {
            continue;
        }
        let Some(method) = methods.get_mut(row.saturating_sub(1) as usize) else {
            continue;
        };
        method.impl_map_token = Some(mapping.token.clone());
        method.pinvoke_module_token = mapping.module_token.clone();
        method.pinvoke_import_name = Some(mapping.import_name.clone());
        method.pinvoke_flags = mapping.flags;
    }
}

fn project_field_rva_data(field_rvas: &mut [FieldRva], pe: &PeLayout, bytes: &[u8]) {
    let mut starts = field_rvas
        .iter()
        .filter_map(|field| field.rva)
        .filter(|rva| *rva != 0)
        .collect::<Vec<_>>();
    starts.sort_unstable();
    starts.dedup();

    for field in field_rvas {
        let Some(rva) = field.rva.filter(|value| *value != 0) else {
            continue;
        };
        let Ok((offset, available)) = pe.available_bytes(bytes, rva) else {
            if field.issue.is_none() {
                field.issue = Some("FieldRVA does not map to file-backed data".to_owned());
            }
            continue;
        };
        let next = starts.iter().copied().find(|next| *next > rva);
        let extent = next
            .map(|next| next.saturating_sub(rva) as usize)
            .unwrap_or(available);
        let length = extent.min(available).min(MAX_FIELD_DATA_BYTES);
        if length == 0 {
            field
                .issue
                .get_or_insert_with(|| "FieldRVA has no readable data".to_owned());
            continue;
        }
        field.data_offset = Some(offset);
        field.data_hex = Some(hex(&bytes[offset..offset + length]));
    }
}

fn validate_interface_impl(
    class: Option<usize>,
    interface: Option<usize>,
    tables: &TableStream,
) -> Option<String> {
    if class.is_none() || interface.is_none() {
        return Some("truncated InterfaceImpl row".to_owned());
    }
    let class = class.unwrap();
    if class == 0 || class > tables.rows[2] as usize {
        return Some("InterfaceImpl declaring type is out of range".to_owned());
    }
    let interface = interface.unwrap();
    let table = [1usize, 2, 27][interface & 3];
    let row = interface >> 2;
    if row == 0 || row > tables.rows[table] as usize {
        return Some("InterfaceImpl interface token is out of range".to_owned());
    }
    None
}

fn validate_method_impl(
    class: Option<usize>,
    body: Option<usize>,
    declaration: Option<usize>,
    tables: &TableStream,
) -> Option<String> {
    if class.is_none() || body.is_none() || declaration.is_none() {
        return Some("truncated MethodImpl row".to_owned());
    }
    let class = class.unwrap();
    if class == 0 || class > tables.rows[2] as usize {
        return Some("MethodImpl declaring type is out of range".to_owned());
    }
    for value in [body.unwrap(), declaration.unwrap()] {
        let table = [6usize, 10][value & 1];
        let row = value >> 1;
        if row == 0 || row > tables.rows[table] as usize {
            return Some("MethodImpl member token is out of range".to_owned());
        }
    }
    None
}

fn project_accessor_ownership(
    property_maps: &[PropertyMap],
    properties: &mut [PropertyDefinition],
    method_semantics: &[MethodSemantic],
    event_maps: &[EventMap],
    events: &mut [EventDefinition],
) {
    for (index, property) in properties.iter_mut().enumerate() {
        let row = index as u32 + 1;
        property.declaring_type_token = owner_for_list_row(
            property_maps
                .iter()
                .map(|map| (&map.parent_type_token, map.property_list)),
            row,
        );
    }

    for (index, event) in events.iter_mut().enumerate() {
        let row = index as u32 + 1;
        event.declaring_type_token = owner_for_list_row(
            event_maps
                .iter()
                .map(|map| (&map.parent_type_token, map.event_list)),
            row,
        );
    }

    for semantic in method_semantics {
        let Some((table, row)) = decode_token(&semantic.association_token) else {
            continue;
        };
        let method = Some(semantic.method_token.clone());
        match table {
            23 => {
                let Some(property) = properties.get_mut(row.saturating_sub(1) as usize) else {
                    continue;
                };
                if semantic.semantics & 0x0002 != 0 {
                    property.getter_method_token = method.clone();
                }
                if semantic.semantics & 0x0001 != 0 {
                    property.setter_method_token = method;
                }
                if semantic.semantics & 0x0004 != 0 {
                    property
                        .other_method_tokens
                        .push(semantic.method_token.clone());
                }
            }
            20 => {
                let Some(event) = events.get_mut(row.saturating_sub(1) as usize) else {
                    continue;
                };
                if semantic.semantics & 0x0008 != 0 {
                    event.add_method_token = method.clone();
                }
                if semantic.semantics & 0x0010 != 0 {
                    event.remove_method_token = method.clone();
                }
                if semantic.semantics & 0x0020 != 0 {
                    event.raise_method_token = method;
                }
                if semantic.semantics & 0x0004 != 0 {
                    event
                        .other_method_tokens
                        .push(semantic.method_token.clone());
                }
            }
            _ => {}
        }
    }
}

fn owner_for_list_row<'a, I>(maps: I, row: u32) -> Option<String>
where
    I: Iterator<Item = (&'a String, u32)>,
{
    maps.filter(|(_, start)| *start != 0 && *start <= row)
        .max_by_key(|(_, start)| *start)
        .map(|(owner, _)| owner.clone())
}

fn decode_token(value: &str) -> Option<(u32, u32)> {
    let value = value.strip_prefix("0x")?;
    let raw = u32::from_str_radix(value, 16).ok()?;
    Some((raw >> 24, raw & 0x00ff_ffff))
}

fn decode_method_impl_flags(flags: u16) -> (&'static str, &'static str, Vec<&'static str>, u16) {
    let code_type = match flags & 0x0003 {
        0 => "il",
        1 => "native",
        2 => "optil",
        3 => "runtime",
        _ => "unknown",
    };
    let managed_status = match flags & 0x0004 {
        0 => "unmanaged",
        _ => "managed",
    };
    let known_flags = [
        (0x0008, "no-inlining"),
        (0x0010, "forward-reference"),
        (0x0020, "synchronized"),
        (0x0040, "no-optimization"),
        (0x0080, "preserve-signature"),
        (0x0100, "aggressive-inlining"),
        (0x0200, "aggressive-optimization"),
        (0x1000, "internal-call"),
    ];
    let names = known_flags
        .iter()
        .copied()
        .filter_map(|(mask, name)| (flags & mask != 0).then_some(name))
        .collect();
    let known_mask = 0x0007 | known_flags.iter().fold(0, |mask, (value, _)| mask | value);
    (code_type, managed_status, names, flags & !known_mask)
}

fn decode_impl_map_flags(flags: u16) -> (Vec<&'static str>, u16) {
    let known = [
        (0x0001, "no-mangle"),
        (0x0002, "charset-ansi"),
        (0x0004, "charset-unicode"),
        (0x0006, "charset-auto"),
        (0x0010, "best-fit-enabled"),
        (0x0020, "best-fit-disabled"),
        (0x0040, "supports-last-error"),
        (0x0100, "calling-convention-platformapi"),
        (0x0200, "calling-convention-cdecl"),
        (0x0300, "calling-convention-stdcall"),
        (0x0400, "calling-convention-thiscall"),
        (0x0500, "calling-convention-fastcall"),
        (0x0600, "calling-convention-vararg"),
        (0x0700, "calling-convention-lastwinapi"),
        (0x1000, "throw-on-unmappable-enabled"),
        (0x2000, "throw-on-unmappable-disabled"),
    ];
    let names = known
        .iter()
        .filter_map(|(mask, name)| (flags & mask == *mask).then_some(*name))
        .collect();
    let known_mask = 0x0001 | 0x0006 | 0x0030 | 0x0040 | 0x0700 | 0x3000;
    (names, flags & !known_mask)
}

fn decode_method_semantics_flags(flags: u16) -> (Vec<&'static str>, u16) {
    let known = [
        (0x0001, "setter"),
        (0x0002, "getter"),
        (0x0004, "other"),
        (0x0008, "add"),
        (0x0010, "remove"),
        (0x0020, "raise"),
    ];
    let names = known
        .iter()
        .filter_map(|(mask, name)| (flags & mask != 0).then_some(*name))
        .collect();
    (names, flags & !0x003f)
}

fn coded_token(value: usize, tag_bits: usize, tables: &[usize]) -> String {
    let tag = value & ((1 << tag_bits) - 1);
    let row = (value >> tag_bits) as u32;
    tables
        .get(tag)
        .map(|table| token(*table as u32, row))
        .unwrap_or_else(|| format!("0x{value:08x}"))
}

fn custom_attribute_parent_token(value: usize) -> String {
    coded_token(
        value,
        5,
        &[
            0, 1, 2, 4, 6, 8, 9, 10, 12, 14, 17, 20, 23, 26, 27, 32, 35, 38, 39, 40, 42, 43, 44,
        ],
    )
}

fn custom_attribute_constructor_token(value: usize) -> String {
    let tag = value & 0x7;
    let row = (value >> 3) as u32;
    match tag {
        2 => token(6, row),
        3 => token(10, row),
        _ => format!("0x{value:08x}"),
    }
}

fn decode_native_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() != 1 {
        return None;
    }
    Some(match bytes[0] {
        0x01 => "void",
        0x02 => "bool",
        0x03 => "i8",
        0x04 => "u8",
        0x05 => "i16",
        0x06 => "u16",
        0x07 => "i32",
        0x08 => "u32",
        0x09 => "i64",
        0x0a => "u64",
        0x0b => "f32",
        0x0c => "f64",
        0x14 => "lpstr",
        0x15 => "lpwstr",
        0x16 => "lptstr",
        0x1c => "object",
        _ => return None,
    })
}

fn attach_custom_attributes(
    attributes: Vec<CustomAttribute>,
    assembly: &mut Option<Assembly>,
    types: &mut [TypeDefinition],
    methods: &mut [MethodDefinition],
    fields: &mut [FieldDefinition],
    properties: &mut [PropertyDefinition],
    events: &mut [EventDefinition],
) -> Vec<CustomAttribute> {
    for attribute in &attributes {
        let Some((table, row)) = attribute.parent_token.as_deref().and_then(decode_token) else {
            continue;
        };
        match table {
            32 if row == 1 => {
                if let Some(value) = assembly.as_mut() {
                    value.custom_attributes.push(attribute.clone());
                }
            }
            2 => attach_to(types.get_mut(row.saturating_sub(1) as usize), attribute),
            6 => attach_to(methods.get_mut(row.saturating_sub(1) as usize), attribute),
            4 => attach_to(fields.get_mut(row.saturating_sub(1) as usize), attribute),
            23 => attach_to(
                properties.get_mut(row.saturating_sub(1) as usize),
                attribute,
            ),
            20 => attach_to(events.get_mut(row.saturating_sub(1) as usize), attribute),
            _ => {}
        }
    }
    attributes
}

fn project_local_signatures(methods: &mut [MethodDefinition], signatures: &[StandaloneSignature]) {
    for method in methods {
        let Some(token) = method.body.local_signature_token.as_deref() else {
            continue;
        };
        let Some(signature) = signatures.iter().find(|item| item.token == token) else {
            method.body.issue = Some(
                "method local signature token does not resolve to a StandAloneSig row".to_owned(),
            );
            continue;
        };
        method.body.local_signature = Some(signature.signature.clone());
        if signature.issue.is_some() {
            method.body.issue = signature.issue.clone();
        }
    }
}

fn project_user_strings(methods: &mut [MethodDefinition], heap: &[u8]) {
    for method in methods {
        for anchor in &mut method.body.anchors {
            if anchor.opcode != "0x72" {
                continue;
            }
            let Some(operand) = anchor.operand.as_deref() else {
                anchor.user_string_issue = Some("ldstr operand is missing".to_owned());
                continue;
            };
            let Some(raw_token) = operand.strip_prefix("0x") else {
                anchor.user_string_issue = Some("ldstr operand is not a token".to_owned());
                continue;
            };
            let Ok(token) = u32::from_str_radix(raw_token, 16) else {
                anchor.user_string_issue = Some("ldstr operand token is malformed".to_owned());
                continue;
            };
            if token >> 24 != 0x70 {
                anchor.user_string_issue =
                    Some("ldstr operand is not a user-string token".to_owned());
                continue;
            }
            let offset = (token & 0x00ff_ffff) as usize;
            anchor.user_string_offset = Some(offset);
            match decode_user_string(heap, offset) {
                Ok(value) => anchor.user_string = Some(value),
                Err(issue) => anchor.user_string_issue = Some(issue.to_owned()),
            }
        }
    }
}

fn project_constants(
    constants: &[Constant],
    fields: &mut [FieldDefinition],
    params: &mut [ParameterDefinition],
    properties: &mut [PropertyDefinition],
) {
    for constant in constants {
        let Some((table, row)) = constant.parent_token.as_deref().and_then(decode_token) else {
            continue;
        };
        match table {
            4 => fields
                .get_mut(row.saturating_sub(1) as usize)
                .map(|item| item.constants.push(constant.clone())),
            8 => params
                .get_mut(row.saturating_sub(1) as usize)
                .map(|item| item.constants.push(constant.clone())),
            23 => properties
                .get_mut(row.saturating_sub(1) as usize)
                .map(|item| item.constants.push(constant.clone())),
            _ => None,
        };
    }
}

fn project_parameter_ownership(methods: &[MethodDefinition], params: &mut [ParameterDefinition]) {
    for (method_index, method) in methods.iter().enumerate() {
        let start = method.param_list.max(1) as usize;
        let end = methods
            .get(method_index + 1)
            .map(|next| next.param_list.max(start as u32) as usize)
            .unwrap_or(params.len() + 1);
        if start > params.len() + 1 || end > params.len() + 1 || start > end {
            continue;
        }
        for param in params
            .get_mut(start.saturating_sub(1)..end.saturating_sub(1))
            .unwrap_or(&mut [])
        {
            param.method_token = Some(method.token.clone());
        }
    }
    for param in params {
        if param.method_token.is_none() {
            param.issue =
                Some("Parameter row is not owned by a MethodDef ParamList range".to_owned());
        }
    }
}

fn decode_constant(element_type: u8, value: &[u8]) -> Option<String> {
    let read = |size| value.get(..size);
    match element_type {
        0x02 => read(1).map(|bytes| (bytes[0] != 0).to_string()),
        0x03 => read(2).map(|bytes| format!("{}", u16::from_le_bytes([bytes[0], bytes[1]]))),
        0x04 => read(1).map(|bytes| (bytes[0] as i8).to_string()),
        0x05 => read(1).map(|bytes| bytes[0].to_string()),
        0x06 => read(2).map(|bytes| i16::from_le_bytes([bytes[0], bytes[1]]).to_string()),
        0x07 => read(2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]).to_string()),
        0x08 => read(4)
            .map(|bytes| i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()),
        0x09 => read(4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()),
        0x0a => read(8).map(|bytes| i64::from_le_bytes(bytes.try_into().unwrap()).to_string()),
        0x0b => read(8).map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()).to_string()),
        0x0c => read(4)
            .map(|bytes| f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()),
        0x0d => read(8).map(|bytes| f64::from_le_bytes(bytes.try_into().unwrap()).to_string()),
        0x0e => String::from_utf16(
            &value
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )
        .ok(),
        0x12 => (value.is_empty()).then(|| "null".to_owned()),
        _ => None,
    }
}

fn decode_user_string(heap: &[u8], offset: usize) -> Result<String, &'static str> {
    if offset == 0 || offset >= heap.len() {
        return Err("user-string heap offset is out of bounds");
    }
    let mut at = offset;
    let length = compressed(heap, &mut at).ok_or("user-string length is malformed")?;
    let end = at
        .checked_add(length)
        .ok_or("user-string range overflows")?;
    let bytes = heap
        .get(at..end)
        .ok_or("user-string payload is truncated")?;
    let payload = if bytes.len() % 2 == 1 {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    let units = payload
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| "user-string contains invalid UTF-16")
}

fn attach_to<T>(target: Option<&mut T>, attribute: &CustomAttribute)
where
    T: CustomAttributeOwner,
{
    if let Some(target) = target {
        target.custom_attributes_mut().push(attribute.clone());
    }
}

trait CustomAttributeOwner {
    fn custom_attributes_mut(&mut self) -> &mut Vec<CustomAttribute>;
}

impl CustomAttributeOwner for TypeDefinition {
    fn custom_attributes_mut(&mut self) -> &mut Vec<CustomAttribute> {
        &mut self.custom_attributes
    }
}
impl CustomAttributeOwner for MethodDefinition {
    fn custom_attributes_mut(&mut self) -> &mut Vec<CustomAttribute> {
        &mut self.custom_attributes
    }
}
impl CustomAttributeOwner for FieldDefinition {
    fn custom_attributes_mut(&mut self) -> &mut Vec<CustomAttribute> {
        &mut self.custom_attributes
    }
}
impl CustomAttributeOwner for PropertyDefinition {
    fn custom_attributes_mut(&mut self) -> &mut Vec<CustomAttribute> {
        &mut self.custom_attributes
    }
}
impl CustomAttributeOwner for EventDefinition {
    fn custom_attributes_mut(&mut self) -> &mut Vec<CustomAttribute> {
        &mut self.custom_attributes
    }
}

fn token(table: u32, row: u32) -> String {
    format!("0x{:08x}", (table << 24) | row)
}
fn code_view(bytes: &[u8], pe: &PeLayout) -> Option<CodeView> {
    if pe.debug_rva == 0 || pe.debug_size < 28 {
        return None;
    }
    let directory = pe
        .map(bytes, pe.debug_rva, pe.debug_size.min(4096) as usize)
        .ok()?;
    let entries = (pe.debug_size.min(4096) as usize) / 28;
    for index in 0..entries {
        let at = directory + index * 28;
        if u32(bytes, at + 12).ok()? != 2 {
            continue;
        }
        let size = u32(bytes, at + 16).ok()?;
        if size < 16 || size > 4096 {
            continue;
        }
        let mut data = u32(bytes, at + 24).ok()? as usize;
        if data == 0 {
            data = pe
                .map(bytes, u32(bytes, at + 20).ok()?, size.min(4096) as usize)
                .ok()?;
        }
        let record = bytes.get(data..data + size.min(4096) as usize)?;
        let magic = &record[..4];
        let (format, path_at, guid, age) = if magic == b"RSDS" && record.len() >= 24 {
            let guid = format!(
                "{:08x}-{:04x}-{:04x}-{}-{}",
                u32(record, 4).ok()?,
                u16(record, 8).ok()?,
                u16(record, 10).ok()?,
                hex(&record[12..14]),
                hex(&record[14..20])
            );
            ("RSDS", 24, Some(guid), u32(record, 20).ok()?)
        } else if magic == b"NB10" && record.len() >= 16 {
            ("NB10", 16, None, u32(record, 12).ok()?)
        } else {
            continue;
        };
        let end = record[path_at..].iter().position(|byte| *byte == 0)? + path_at;
        if end <= path_at {
            continue;
        }
        let pdb_path = String::from_utf8_lossy(&record[path_at..end]).into_owned();
        let pdb_file_name = pdb_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&pdb_path)
            .to_owned();
        return Some(CodeView {
            format,
            pdb_path,
            pdb_file_name,
            guid,
            age,
            data_offset: data,
        });
    }
    None
}
fn method_body(bytes: &[u8], pe: &PeLayout, rva: u32) -> MethodBody {
    let absent = |status, issue| MethodBody {
        status,
        header_format: "none",
        rva,
        file_offset: None,
        max_stack: None,
        init_locals: None,
        il_size: 0,
        il_sha256: None,
        normalized_il_sha256: None,
        instruction_count: 0,
        decoded_instruction_count: 0,
        truncated_instructions: 0,
        opcode_counts: std::collections::BTreeMap::new(),
        anchors: Vec::new(),
        issue,
        exception_regions: Vec::new(),
        local_signature_token: None,
        local_signature: None,
        local_signature_source_range: None,
    };
    if rva == 0 {
        return absent("absent", None);
    }
    let Ok(at) = pe.map(bytes, rva, 1) else {
        return absent("malformed", Some("method RVA is not file-backed".into()));
    };
    let first = bytes[at];
    let (format, header, size) = if first & 3 == 2 {
        ("tiny", 1usize, usize::from(first >> 2))
    } else if first & 3 == 3 {
        let words = usize::from(first >> 4);
        let h = words.saturating_mul(4);
        let Ok(code) = u32(bytes, at + 4) else {
            return absent("malformed", Some("fat method header is truncated".into()));
        };
        ("fat", h, code as usize)
    } else {
        return absent(
            "malformed",
            Some("method header format is unsupported".into()),
        );
    };
    let local_signature_token = (format == "fat")
        .then(|| u32(bytes, at + 8).ok())
        .flatten()
        .filter(|value| *value != 0)
        .map(|value| format!("0x{value:08x}"));
    let local_signature_source_range = (format == "fat").then_some([at + 8, at + 12]);
    if size > 1024 * 1024 {
        return absent(
            "partial",
            Some("method body exceeds the 1 MiB decoding budget".into()),
        );
    }
    let Ok(il_at) = pe.map(bytes, rva.saturating_add(header as u32), size) else {
        return absent("malformed", Some("method IL is truncated".into()));
    };
    let il = &bytes[il_at..il_at + size];
    let mut counts = std::collections::BTreeMap::new();
    let mut anchors = Vec::new();
    let mut cursor = 0;
    let mut decoded = 0;
    while cursor < il.len() {
        let start = cursor;
        let first = il[cursor];
        cursor += 1;
        let second_opcode = if first == 0xfe {
            let second = il.get(cursor).copied();
            if second.is_some() {
                cursor += 1;
            }
            second
        } else {
            None
        };
        let opcode = if let Some(second) = second_opcode {
            format!("0x{first:02x}{second:02x}")
        } else {
            format!("0x{first:02x}")
        };
        let operand_len = match second_opcode {
            Some(second) => extended_operand_length(second, il.get(cursor..).unwrap_or_default()),
            None if first == 0xfe => usize::MAX,
            None => operand_length(first, il.get(cursor..).unwrap_or_default()),
        };
        if cursor
            .checked_add(operand_len)
            .is_none_or(|end| end > il.len())
        {
            return MethodBody {
                status: "partial",
                header_format: format,
                rva,
                file_offset: Some(il_at),
                max_stack: None,
                init_locals: None,
                il_size: size,
                il_sha256: Some(digest(il)),
                normalized_il_sha256: None,
                instruction_count: anchors.len() + 1,
                decoded_instruction_count: decoded,
                truncated_instructions: 1,
                opcode_counts: counts,
                anchors,
                issue: Some("instruction operand is truncated".into()),
                exception_regions: Vec::new(),
                local_signature_token: local_signature_token.clone(),
                local_signature: None,
                local_signature_source_range,
            };
        }
        let prefixed_token = first == 0xfe && matches!(second_opcode, Some(0x15 | 0x16 | 0x1c));
        let operand = if operand_len == 4
            && (prefixed_token
                || matches!(
                    first,
                    0x28 | 0x29 | 0x6f | 0x72 | 0x73 | 0x74 | 0x75 | 0x7b..=0x80
                )) {
            Some(format!(
                "0x{:08x}",
                u32::from_le_bytes(il[cursor..cursor + 4].try_into().unwrap())
            ))
        } else if is_branch_opcode(first) {
            branch_target(start, first, operand_len, il.get(cursor..))
        } else if first == 0x45 {
            switch_operand_count(il.get(cursor..))
        } else {
            prefixed_operand_value(second_opcode, il.get(cursor..))
                .or_else(|| variable_or_literal_operand(first, il.get(cursor..)))
        };
        cursor += operand_len;
        *counts.entry(opcode.clone()).or_insert(0) += 1;
        if anchors.len() < 256 {
            anchors.push(InstructionAnchor {
                il_offset: start,
                opcode,
                operand_kind: if operand.is_some() {
                    operand_kind(first, second_opcode)
                } else if operand_len > 0 {
                    "constant"
                } else {
                    "none"
                },
                operand,
                user_string: None,
                user_string_offset: None,
                user_string_issue: None,
            });
        }
        decoded += 1;
    }
    let (exception_regions, exception_issue) = if format == "fat" && first & 0x08 != 0 {
        match exception_regions(bytes, il_at + size, size) {
            Ok(regions) => (regions, None),
            Err(issue) => (Vec::new(), Some(issue)),
        }
    } else {
        (Vec::new(), None)
    };
    MethodBody {
        status: "present",
        header_format: format,
        rva,
        file_offset: Some(il_at),
        max_stack: (format == "fat").then(|| u16(bytes, at + 6).unwrap_or(0)),
        init_locals: (format == "fat").then(|| u16(bytes, at).unwrap_or(0) & 0x10 != 0),
        il_size: size,
        il_sha256: Some(digest(il)),
        normalized_il_sha256: Some(normalized_il_digest(&anchors)),
        instruction_count: decoded,
        decoded_instruction_count: decoded,
        truncated_instructions: 0,
        opcode_counts: counts,
        anchors,
        issue: exception_issue,
        exception_regions,
        local_signature_token,
        local_signature: None,
        local_signature_source_range,
    }
}
fn exception_regions(
    bytes: &[u8],
    section_at: usize,
    il_size: usize,
) -> Result<Vec<ExceptionRegion>, String> {
    let aligned = (section_at + 3) & !3;
    let kind = *bytes
        .get(aligned)
        .ok_or("exception section header is truncated")?;
    if kind & 0x3f != 1 {
        return Err("unsupported method data section kind".into());
    }
    let fat = kind & 0x40 != 0;
    let data_size = if fat {
        u32(bytes, aligned + 1).map_err(|_| "fat exception section size is truncated")? as usize
            & 0x00ff_ffff
    } else {
        usize::from(
            *bytes
                .get(aligned + 1)
                .ok_or("exception section size is truncated")?,
        )
    };
    let section_end = aligned
        .checked_add(data_size)
        .ok_or("exception section size overflows artifact")?;
    if data_size < 4 || section_end > bytes.len() {
        return Err("exception section size leaves artifact".into());
    }
    if !fat && (bytes.get(aligned + 2) != Some(&0) || bytes.get(aligned + 3) != Some(&0)) {
        return Err("small exception section reserved bytes are nonzero".into());
    }
    let clause_size = if fat { 24 } else { 12 };
    if (data_size - 4) % clause_size != 0 {
        return Err("exception section clause area is malformed".into());
    }
    let count = (data_size - 4) / clause_size;
    if count > 4096 {
        return Err("exception section exceeds the 4096-clause budget".into());
    }
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let at = aligned + 4 + index * clause_size;
        let flags = if fat {
            u32(bytes, at).map_err(|_| "exception clause is truncated")?
        } else {
            u16(bytes, at).map_err(|_| "exception clause is truncated")? as u32
        };
        let (try_offset, try_length, handler_offset, handler_length, token_or_filter) = if fat {
            (
                u32(bytes, at + 4).map_err(|_| "exception clause is truncated")? as usize,
                u32(bytes, at + 8).map_err(|_| "exception clause is truncated")? as usize,
                u32(bytes, at + 12).map_err(|_| "exception clause is truncated")? as usize,
                u32(bytes, at + 16).map_err(|_| "exception clause is truncated")? as usize,
                u32(bytes, at + 20).map_err(|_| "exception clause is truncated")?,
            )
        } else {
            (
                u16(bytes, at + 2).map_err(|_| "exception clause is truncated")? as usize,
                usize::from(*bytes.get(at + 4).ok_or("exception clause is truncated")?),
                u16(bytes, at + 5).map_err(|_| "exception clause is truncated")? as usize,
                usize::from(*bytes.get(at + 7).ok_or("exception clause is truncated")?),
                u32(bytes, at + 8).map_err(|_| "exception clause is truncated")?,
            )
        };
        if try_offset
            .checked_add(try_length)
            .is_none_or(|end| end > il_size)
            || handler_offset
                .checked_add(handler_length)
                .is_none_or(|end| end > il_size)
        {
            return Err("exception clause range exceeds method IL".into());
        }
        out.push(ExceptionRegion {
            flags,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            class_token: (flags & 1 == 0).then(|| format!("0x{token_or_filter:08x}")),
            filter_offset: (flags & 1 != 0).then_some(token_or_filter as usize),
        });
    }
    Ok(out)
}
fn token_operand_kind(opcode: u8) -> &'static str {
    match opcode {
        0x0e..=0x13 => "variable",
        0x1f | 0x20 | 0x21 | 0x22 | 0x23 => "constant",
        0x2b | 0x2c..=0x37 | 0x38..=0x44 => "branch",
        0x28 | 0x6f | 0x73 => "method",
        0x29 => "signature",
        0x7b..=0x80 => "field",
        0x72 => "string",
        0x74 | 0x75 | 0xd0 => "type",
        0x45 => "switch",
        _ => "token",
    }
}

fn operand_kind(opcode: u8, second: Option<u8>) -> &'static str {
    if opcode == 0xfe {
        return match second {
            Some(0x09..=0x0e) => "variable",
            Some(0x15 | 0x16 | 0x1c) => "type",
            Some(0x19) => "constant",
            _ => "token",
        };
    }
    token_operand_kind(opcode)
}

fn prefixed_operand_value(second: Option<u8>, remaining: Option<&[u8]>) -> Option<String> {
    let second = second?;
    let bytes = remaining?;
    if matches!(second, 0x09..=0x0e) {
        return Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?).to_string());
    }
    None
}

fn literal_operand(opcode: u8, remaining: Option<&[u8]>) -> Option<String> {
    let bytes = remaining?;
    match opcode {
        0x1f => Some(i8::from_le_bytes([*bytes.first()?]).to_string()),
        0x20 => Some(i32::from_le_bytes(bytes.get(..4)?.try_into().ok()?).to_string()),
        0x21 => Some(i64::from_le_bytes(bytes.get(..8)?.try_into().ok()?).to_string()),
        0x22 => Some(f32::from_le_bytes(bytes.get(..4)?.try_into().ok()?).to_string()),
        0x23 => Some(f64::from_le_bytes(bytes.get(..8)?.try_into().ok()?).to_string()),
        _ => None,
    }
}

fn variable_or_literal_operand(opcode: u8, remaining: Option<&[u8]>) -> Option<String> {
    if matches!(opcode, 0x0e..=0x13) {
        return remaining?.first().map(|value| value.to_string());
    }
    literal_operand(opcode, remaining)
}

fn is_branch_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x2b..=0x38 | 0x39..=0x44)
}

fn branch_target(
    instruction_start: usize,
    opcode: u8,
    operand_length: usize,
    remaining: Option<&[u8]>,
) -> Option<String> {
    let bytes = remaining?;
    let delta = if opcode == 0x2b {
        i8::from_le_bytes([*bytes.first()?]) as i64
    } else {
        i32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as i64
    };
    let next = instruction_start.checked_add(1 + operand_length)? as i64;
    let target = next.checked_add(delta)?;
    (target >= 0).then(|| format!("0x{target:08x}"))
}

fn switch_operand_count(remaining: Option<&[u8]>) -> Option<String> {
    let bytes = remaining?;
    let count = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    Some(count.to_string())
}

fn switch_operand_length(remaining: &[u8]) -> Option<usize> {
    let count = u32::from_le_bytes(remaining.get(..4)?.try_into().ok()?) as usize;
    count.checked_mul(4)?.checked_add(4)
}

fn normalized_il_digest(anchors: &[InstructionAnchor]) -> String {
    let tuples: Vec<(&str, &str, Option<&str>)> = anchors
        .iter()
        .map(|anchor| {
            (
                anchor.opcode.as_str(),
                anchor.operand_kind,
                anchor.operand.as_deref(),
            )
        })
        .collect();
    let encoded = serde_json::to_vec(&tuples).unwrap_or_default();
    digest(&encoded)
}

fn operand_length(opcode: u8, rest: &[u8]) -> usize {
    match opcode {
        0x0e | 0x0f | 0x10 | 0x11 | 0x12 | 0x13 | 0x1f | 0x2b..=0x37 | 0xde => 1,
        0x15
        | 0x16
        | 0x17
        | 0x18
        | 0x19
        | 0x1a
        | 0x1b
        | 0x1c
        | 0x1d
        | 0x1e
        | 0x20
        | 0x21
        | 0x22
        | 0x23
        | 0x28
        | 0x29
        | 0x38..=0x44
        | 0x6f
        | 0x70
        | 0x71
        | 0x72
        | 0x73
        | 0x74
        | 0x75
        | 0x76
        | 0x77
        | 0x78
        | 0x79
        | 0x7a
        | 0x7b
        | 0x7c
        | 0x7d
        | 0x7e
        | 0x7f
        | 0x80
        | 0x81
        | 0x8c
        | 0x8d
        | 0x8e
        | 0x8f
        | 0x90
        | 0x91
        | 0x92
        | 0x93
        | 0x94
        | 0x95
        | 0x96
        | 0x97
        | 0x98
        | 0x99
        | 0x9a
        | 0x9b
        | 0x9c
        | 0x9d
        | 0x9e
        | 0x9f
        | 0xa0
        | 0xa1
        | 0xa2
        | 0xa3
        | 0xa4
        | 0xa5
        | 0xa6
        | 0xa7
        | 0xb3
        | 0xb4
        | 0xb5
        | 0xb6
        | 0xb7
        | 0xb8
        | 0xb9
        | 0xba
        | 0xbb
        | 0xbc
        | 0xbd
        | 0xbe
        | 0xbf
        | 0xc0
        | 0xc1
        | 0xc2
        | 0xc3
        | 0xc4
        | 0xc5
        | 0xc6
        | 0xc7
        | 0xc8
        | 0xc9
        | 0xca
        | 0xcb
        | 0xcc
        | 0xcd
        | 0xce
        | 0xcf
        | 0xd0 => 4,
        _ => {
            if opcode == 0x45 {
                switch_operand_length(rest).unwrap_or(usize::MAX)
            } else {
                0
            }
        }
    }
}

fn extended_operand_length(opcode: u8, _rest: &[u8]) -> usize {
    match opcode {
        0x09..=0x0e => 2,
        0x15 | 0x16 | 0x1c => 4,
        0x19 => 1,
        _ => 0,
    }
}
fn table_index_width(t: &TableStream, table: usize) -> usize {
    if t.rows[table] >= 65_536 { 4 } else { 2 }
}

struct AssemblyPublicKeyIdentity {
    kind: &'static str,
    byte_length: usize,
    sha256: Option<String>,
    token: Option<String>,
}

fn assembly_public_key_identity(
    flags: u32,
    offset: usize,
    key: Option<&[u8]>,
) -> AssemblyPublicKeyIdentity {
    let Some(key) = key.filter(|key| !key.is_empty()) else {
        return AssemblyPublicKeyIdentity {
            kind: "none",
            byte_length: 0,
            sha256: None,
            token: None,
        };
    };

    let kind = if flags & 1 == 0 {
        "public-key-token"
    } else {
        "public-key"
    };
    let token = if flags & 1 == 0 {
        (offset != 0 && key.len() == 8).then(|| hex(key))
    } else {
        let mut hasher = Sha1::new();
        Sha1Digest::update(&mut hasher, key);
        let digest = Sha1Digest::finalize(hasher);
        Some(hex(&digest[12..].iter().rev().copied().collect::<Vec<_>>()))
    };

    AssemblyPublicKeyIdentity {
        kind,
        byte_length: key.len(),
        sha256: Some(digest(key)),
        token,
    }
}

fn coded_width(t: &TableStream, tag_bits: usize, tables: &[usize]) -> usize {
    let max = tables.iter().map(|table| t.rows[*table]).max().unwrap_or(0);
    if max >= (1u32 << (16 - tag_bits)) {
        4
    } else {
        2
    }
}
fn blob_value(heap: &[u8], index: usize) -> Option<Vec<u8>> {
    if index == 0 || index >= heap.len() {
        return None;
    }
    let first = heap[index];
    let (length, start) = if first & 0x80 == 0 {
        (first as usize, index + 1)
    } else if first & 0xc0 == 0x80 {
        (
            ((u16::from(first & 0x3f) << 8) | u16::from(*heap.get(index + 1)?)) as usize,
            index + 2,
        )
    } else {
        (
            ((u32::from(first & 0x1f) << 24)
                | (u32::from(*heap.get(index + 1)?) << 16)
                | (u32::from(*heap.get(index + 2)?) << 8)
                | u32::from(*heap.get(index + 3)?)) as usize,
            index + 4,
        )
    };
    heap.get(start..start.checked_add(length)?)
        .map(ToOwned::to_owned)
}
fn compressed(bytes: &[u8], at: &mut usize) -> Option<usize> {
    let first = *bytes.get(*at)?;
    if first & 0x80 == 0 {
        *at += 1;
        Some(first as usize)
    } else if first & 0xc0 == 0x80 {
        let value = (usize::from(first & 0x3f) << 8) | usize::from(*bytes.get(*at + 1)?);
        *at += 2;
        Some(value)
    } else {
        let value = (usize::from(first & 0x1f) << 24)
            | (usize::from(*bytes.get(*at + 1)?) << 16)
            | (usize::from(*bytes.get(*at + 2)?) << 8)
            | usize::from(*bytes.get(*at + 3)?);
        *at += 4;
        Some(value)
    }
}

fn compressed_signed(bytes: &[u8], at: &mut usize) -> Option<isize> {
    let value = compressed(bytes, at)?;
    let signed = if value & 1 == 0 {
        (value >> 1) as isize
    } else {
        -((value >> 1) as isize) - 1
    };
    Some(signed)
}

fn decode_type(bytes: &[u8], at: &mut usize) -> Option<String> {
    let code = *bytes.get(*at)?;
    *at += 1;
    Some(
        match code {
            0x01 => "void",
            0x02 => "bool",
            0x03 => "char",
            0x04 => "int8",
            0x05 => "uint8",
            0x06 => "int16",
            0x07 => "uint16",
            0x08 => "int32",
            0x09 => "uint32",
            0x0a => "int64",
            0x0b => "uint64",
            0x0c => "float32",
            0x0d => "float64",
            0x0e => "string",
            0x16 => "typedref",
            0x18 => "native-int",
            0x19 => "native-uint",
            0x1c => "object",
            0x1d => return decode_type(bytes, at).map(|inner| format!("{inner}[]")),
            0x14 => return decode_array_type(bytes, at),
            0x15 => return decode_generic_instance(bytes, at),
            0x0f => return decode_type(bytes, at).map(|inner| format!("&{inner}")),
            0x10 => return decode_type(bytes, at).map(|inner| format!("*{inner}")),
            0x11 | 0x12 => {
                return compressed(bytes, at).map(|token| format!("token:0x{token:08x}"));
            }
            0x13 | 0x1e => return compressed(bytes, at).map(|index| format!("generic:{index}")),
            _ => return None,
        }
        .into(),
    )
}

fn decode_array_type(bytes: &[u8], at: &mut usize) -> Option<String> {
    let element = decode_type(bytes, at)?;
    let rank = compressed(bytes, at)?;
    if rank == 0 || rank > 32 {
        return None;
    }
    let size_count = compressed(bytes, at)?;
    if size_count > rank {
        return None;
    }
    for _ in 0..size_count {
        compressed(bytes, at)?;
    }
    let bound_count = compressed(bytes, at)?;
    if bound_count > rank {
        return None;
    }
    for _ in 0..bound_count {
        compressed_signed(bytes, at)?;
    }
    Some(format!(
        "{element}[{}]",
        ",".repeat(rank.saturating_sub(1) as usize)
    ))
}

fn decode_generic_instance(bytes: &[u8], at: &mut usize) -> Option<String> {
    let kind = *bytes.get(*at)?;
    if !matches!(kind, 0x11 | 0x12) {
        return None;
    }
    *at += 1;
    let token = compressed(bytes, at)?;
    let count = compressed(bytes, at)?;
    if count > 32 {
        return None;
    }
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        arguments.push(decode_type(bytes, at)?);
    }
    Some(format!("token:0x{token:08x}<{}>", arguments.join(",")))
}
fn table_start(t: &TableStream, table: usize) -> usize {
    let mut at = t.offset + 24 + t.valid.count_ones() as usize * 4;
    for i in 0..table {
        if t.valid & (1u64 << i) != 0 {
            at += table_width(t, i);
        }
    }
    at
}
fn table_width(t: &TableStream, table: usize) -> usize {
    let row_width = match table {
        0 => {
            2 + if t.heap_sizes & 1 != 0 { 4 } else { 2 }
                + 3 * if t.heap_sizes & 2 != 0 { 4 } else { 2 }
        }
        1 => 2 * if t.heap_sizes & 1 != 0 { 4 } else { 2 } + coded_width(t, 2, &[0, 1, 26, 35]),
        2 => {
            4 + 2 * if t.heap_sizes & 1 != 0 { 4 } else { 2 }
                + coded_width(t, 2, &[1, 2, 27])
                + table_index_width(t, 4)
                + table_index_width(t, 6)
        }
        4 => {
            2 + if t.heap_sizes & 1 != 0 { 4 } else { 2 }
                + if t.heap_sizes & 4 != 0 { 4 } else { 2 }
        }
        8 => 4 + if t.heap_sizes & 1 != 0 { 4 } else { 2 },
        6 => {
            4 + 2
                + 2
                + if t.heap_sizes & 1 != 0 { 4 } else { 2 }
                + if t.heap_sizes & 4 != 0 { 4 } else { 2 }
                + table_index_width(t, 8)
        }
        32 => {
            16 + if t.heap_sizes & 4 != 0 { 4 } else { 2 }
                + 2 * if t.heap_sizes & 1 != 0 { 4 } else { 2 }
        }
        35 => {
            12 + 2 * if t.heap_sizes & 4 != 0 { 4 } else { 2 }
                + 2 * if t.heap_sizes & 1 != 0 { 4 } else { 2 }
        }
        13 => coded_width(t, 1, &[4, 8]) + if t.heap_sizes & 4 != 0 { 4 } else { 2 },
        14 => 2 + coded_width(t, 2, &[2, 6, 32]) + if t.heap_sizes & 4 != 0 { 4 } else { 2 },
        15 => 2 + 4 + table_index_width(t, 2),
        33 => 4,
        34 => 12,
        36 => 4 + table_index_width(t, 35),
        37 => 12 + table_index_width(t, 35),
        38 => {
            4 + if t.heap_sizes & 1 != 0 { 4 } else { 2 }
                + if t.heap_sizes & 4 != 0 { 4 } else { 2 }
        }
        27 => {
            if t.heap_sizes & 4 != 0 {
                4
            } else {
                2
            }
        }
        28 => {
            2 + coded_width(t, 1, &[4, 6])
                + if t.heap_sizes & 1 != 0 { 4 } else { 2 }
                + table_index_width(t, 26)
        }
        29 => 4 + table_index_width(t, 4),
        42 => {
            4 + (if t.rows[2].max(t.rows[6]) >= 32_768 {
                4
            } else {
                2
            }) + if t.heap_sizes & 1 != 0 { 4 } else { 2 }
        }
        43 => {
            (if t.rows[6].max(t.rows[10]) >= 16_384 {
                4
            } else {
                2
            }) + if t.heap_sizes & 4 != 0 { 4 } else { 2 }
        }
        44 => {
            (if t.rows[42] >= 65_536 { 4 } else { 2 })
                + if t.rows[1].max(t.rows[2]).max(t.rows[27]) >= 16_384 {
                    4
                } else {
                    2
                }
        }
        40 => 8 + if t.heap_sizes & 1 != 0 { 4 } else { 2 } + coded_width(t, 2, &[38, 35, 39]),
        39 => 8 + 2 * if t.heap_sizes & 1 != 0 { 4 } else { 2 } + coded_width(t, 2, &[38, 35, 39]),
        41 => 2 * table_index_width(t, 2),
        18 => table_index_width(t, 2) + table_index_width(t, 20),
        9 => table_index_width(t, 2) + coded_width(t, 2, &[1, 2, 27]),
        11 => 4 + coded_width(t, 2, &[4, 8, 23]) + if t.heap_sizes & 4 != 0 { 4 } else { 2 },
        12 => {
            coded_width(
                t,
                5,
                &[
                    0, 1, 2, 4, 6, 8, 9, 10, 12, 14, 17, 20, 23, 26, 27, 32, 35, 38, 39, 40, 42,
                    43, 44,
                ],
            ) + coded_width(t, 3, &[6, 10])
                + if t.heap_sizes & 4 != 0 { 4 } else { 2 }
        }
        17 => {
            if t.heap_sizes & 4 != 0 {
                4
            } else {
                2
            }
        }
        16 => 4 + table_index_width(t, 4),
        20 => 2 + if t.heap_sizes & 1 != 0 { 4 } else { 2 } + coded_width(t, 2, &[1, 2, 27]),
        21 => table_index_width(t, 2) + table_index_width(t, 23),
        23 => {
            2 + if t.heap_sizes & 1 != 0 { 4 } else { 2 }
                + if t.heap_sizes & 4 != 0 { 4 } else { 2 }
        }
        24 => 2 + table_index_width(t, 6) + coded_width(t, 1, &[20, 23]),
        25 => table_index_width(t, 2) + 2 * coded_width(t, 1, &[6, 10]),
        26 => {
            if t.heap_sizes & 1 != 0 {
                4
            } else {
                2
            }
        }
        _ => 0,
    };
    row_width * t.rows[table] as usize
}
fn read_index(b: &[u8], at: &mut usize, width: usize) -> Result<usize, Error> {
    let value = if width == 2 {
        u16(b, *at)? as usize
    } else {
        u32(b, *at)? as usize
    };
    *at += width;
    Ok(value)
}
fn u16(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        slice(b, at, 2)?
            .try_into()
            .map_err(|_| Error::Malformed("truncated metadata"))?,
    ))
}
fn u32(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        slice(b, at, 4)?
            .try_into()
            .map_err(|_| Error::Malformed("truncated metadata"))?,
    ))
}
fn slice<'a>(b: &'a [u8], at: usize, n: usize) -> Result<&'a [u8], Error> {
    b.get(
        at..at
            .checked_add(n)
            .ok_or(Error::Malformed("metadata range overflow"))?,
    )
    .ok_or(Error::Malformed("truncated metadata"))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn decode_attribute_shape(bytes: &[u8]) -> (Option<u16>, Option<u16>, Option<String>) {
    let Some(prolog) = bytes.get(0..2).and_then(|value| value.try_into().ok()) else {
        return (
            None,
            None,
            Some("CustomAttribute blob is missing its serialized prolog".to_owned()),
        );
    };
    let prolog = u16::from_le_bytes(prolog);
    if prolog != 1 {
        return (
            Some(prolog),
            None,
            Some("CustomAttribute serialized prolog is unsupported".to_owned()),
        );
    }

    let Some((_, string_end)) = attribute_string_range(bytes) else {
        return (
            Some(prolog),
            None,
            Some("CustomAttribute fixed argument is unsupported or truncated".to_owned()),
        );
    };
    let Some(named_end) = string_end.checked_add(2) else {
        return (
            Some(prolog),
            None,
            Some("CustomAttribute named-argument count overflows".to_owned()),
        );
    };
    let Some(named_bytes) = bytes.get(string_end..named_end) else {
        return (
            Some(prolog),
            None,
            Some("CustomAttribute named-argument count is truncated".to_owned()),
        );
    };
    (
        Some(prolog),
        Some(u16::from_le_bytes([named_bytes[0], named_bytes[1]])),
        None,
    )
}

fn attribute_string_range(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 3 || bytes[0..2] != [1, 0] {
        return None;
    }
    let (length, prefix_bytes) = match bytes[2] {
        0xff => return None,
        value @ 0..=0x7f => (value as usize, 1),
        value if value & 0xc0 == 0x80 && bytes.len() >= 4 => {
            ((((value & 0x3f) as usize) << 8) | bytes[3] as usize, 2)
        }
        _ => return None,
    };
    let start: usize = 2 + prefix_bytes;
    let end = start.checked_add(length)?;
    bytes.get(start..end)?;
    Some((start, end))
}

fn decode_attribute_string(bytes: &[u8]) -> Option<String> {
    let (start, end) = attribute_string_range(bytes)?;
    std::str::from_utf8(bytes.get(start..end)?)
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_member_list(first_row: u32) -> MemberList {
        MemberList {
            first_row: Some(first_row),
            last_row: None,
            count: 0,
        }
    }

    fn signature() -> Signature {
        Signature {
            raw_length: 0,
            raw_sha256: String::new(),
            resolved_sha256: None,
            parse_status: "unknown",
            calling_convention: None,
            generic_parameter_count: None,
            parameter_count: None,
            return_type: None,
            parameter_types: Vec::new(),
            field_type: None,
            local_types: Vec::new(),
            issue: None,
        }
    }

    #[test]
    fn projects_property_and_event_accessor_ownership() {
        let property_maps = vec![
            PropertyMap {
                token: token(21, 1),
                source_offset: None,
                parent_type_token: token(2, 1),
                property_list: 1,
            },
            PropertyMap {
                token: token(21, 2),
                source_offset: None,
                parent_type_token: token(2, 2),
                property_list: 2,
            },
        ];
        let mut properties = vec![
            PropertyDefinition {
                token: token(23, 1),
                source_offset: None,
                declaring_type_token: None,
                getter_method_token: None,
                setter_method_token: None,
                other_method_tokens: Vec::new(),
                custom_attributes: Vec::new(),
                constants: Vec::new(),
                flags: 0,
                name: "First".to_owned(),
                signature: signature(),
            },
            PropertyDefinition {
                token: token(23, 2),
                source_offset: None,
                declaring_type_token: None,
                getter_method_token: None,
                setter_method_token: None,
                other_method_tokens: Vec::new(),
                custom_attributes: Vec::new(),
                constants: Vec::new(),
                flags: 0,
                name: "Second".to_owned(),
                signature: signature(),
            },
        ];
        let event_maps = vec![EventMap {
            token: token(18, 1),
            source_offset: None,
            parent_type_token: token(2, 2),
            event_list: 1,
        }];
        let mut events = vec![EventDefinition {
            token: token(20, 1),
            source_offset: None,
            declaring_type_token: None,
            add_method_token: None,
            remove_method_token: None,
            raise_method_token: None,
            other_method_tokens: Vec::new(),
            custom_attributes: Vec::new(),
            flags: 0,
            name: "Changed".to_owned(),
            event_type_token: token(1, 1),
        }];
        let semantics = vec![
            MethodSemantic {
                token: token(24, 1),
                source_offset: None,
                semantics: 0x0002,
                flag_names: vec!["getter"],
                unknown_flags: 0,
                method_token: token(6, 4),
                association_token: token(23, 1),
                association_kind: "property",
                issue: None,
            },
            MethodSemantic {
                token: token(24, 2),
                source_offset: None,
                semantics: 0x0008,
                flag_names: vec!["add"],
                unknown_flags: 0,
                method_token: token(6, 5),
                association_token: token(20, 1),
                association_kind: "event",
                issue: None,
            },
        ];

        project_accessor_ownership(
            &property_maps,
            &mut properties,
            &semantics,
            &event_maps,
            &mut events,
        );

        assert_eq!(properties[0].declaring_type_token, Some(token(2, 1)));
        assert_eq!(properties[1].declaring_type_token, Some(token(2, 2)));
        assert_eq!(properties[0].getter_method_token, Some(token(6, 4)));
        assert_eq!(events[0].declaring_type_token, Some(token(2, 2)));
        assert_eq!(events[0].add_method_token, Some(token(6, 5)));
    }

    #[test]
    fn decodes_method_semantics_flags_and_association_tokens() {
        let mut rows = vec![0; 64];
        rows[6] = 1;
        rows[20] = 1;
        rows[23] = 1;
        rows[24] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 6) | (1u64 << 20) | (1u64 << 24),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 62];
        bytes[56..58].copy_from_slice(&0x8002u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&1u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes());

        let semantics = root.method_semantics(&bytes);

        assert_eq!(semantics.len(), 1);
        assert_eq!(semantics[0].source_offset, Some(56));
        assert_eq!(semantics[0].flag_names, vec!["getter"]);
        assert_eq!(semantics[0].unknown_flags, 0x8000);
        assert_eq!(semantics[0].method_token, token(6, 1));
        assert_eq!(semantics[0].association_token, token(23, 1));
        assert_eq!(semantics[0].association_kind, "property");
        assert_eq!(semantics[0].issue, None);
    }

    #[test]
    fn preserves_invalid_method_semantics_association_as_issue() {
        let mut rows = vec![0; 64];
        rows[24] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 24,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let semantics = root.method_semantics(&vec![0; 38]);

        assert_eq!(semantics.len(), 1);
        assert_eq!(
            semantics[0].issue.as_deref(),
            Some("MethodSemantics method reference is out of range")
        );
    }

    #[test]
    fn decodes_interface_and_method_impl_coded_tokens() {
        assert_eq!(coded_token((3 << 2) | 1, 2, &[1, 2, 27]), token(2, 3));
        assert_eq!(coded_token((7 << 1) | 1, 1, &[6, 10]), token(10, 7));
        assert_eq!(coded_token(0, 1, &[6, 10]), token(6, 0));
    }

    #[test]
    fn classifies_method_and_field_token_operands_for_edges() {
        assert_eq!(token_operand_kind(0x28), "method");
        assert_eq!(token_operand_kind(0x6f), "method");
        assert_eq!(token_operand_kind(0x7b), "field");
        assert_eq!(token_operand_kind(0x80), "field");
        assert_eq!(token_operand_kind(0x72), "string");
        assert_eq!(token_operand_kind(0x74), "type");
        assert_eq!(target_kind("0x06000001"), "method-def");
        assert_eq!(target_kind("0x0a000001"), "member-ref");
        assert_eq!(target_kind("0x2b000001"), "method-spec");
        assert_eq!(target_kind("0x70000001"), "unknown");
    }

    #[test]
    fn projects_member_reference_parent_names_from_type_facts() {
        let mut references = vec![MemberReference {
            token: token(10, 1),
            row_offset: Some(24),
            name: "Run".to_owned(),
            parent_token: Some(token(1, 1)),
            parent_name: None,
            signature: signature(),
        }];
        let types = Vec::new();
        let type_references = vec![TypeReference {
            token: token(1, 1),
            source_offset: Some(10),
            name: "Worker".to_owned(),
            namespace: "Example".to_owned(),
            raw_resolution_scope: None,
            resolution_scope_kind: None,
            resolution_scope_token: None,
            issue: None,
        }];

        project_member_reference_parents(&mut references, &types, &type_references, &[]);

        assert_eq!(references[0].parent_name.as_deref(), Some("Example.Worker"));
    }

    #[test]
    fn preserves_unknown_member_reference_type_spec_parent_names() {
        let mut references = vec![MemberReference {
            token: token(10, 1),
            row_offset: None,
            name: "Invoke".to_owned(),
            parent_token: Some(token(27, 1)),
            parent_name: Some("stale value".to_owned()),
            signature: signature(),
        }];

        project_member_reference_parents(&mut references, &[], &[], &[]);

        assert_eq!(references[0].parent_name, None);
    }

    #[test]
    fn resolves_decoded_type_spec_member_reference_parent_names() {
        let mut references = vec![MemberReference {
            token: token(10, 1),
            row_offset: None,
            name: "Invoke".to_owned(),
            parent_token: Some(token(27, 1)),
            parent_name: None,
            signature: signature(),
        }];
        let mut type_signature = signature();
        type_signature.parse_status = "decoded";
        type_signature.field_type = Some("Example.Worker[]".to_owned());
        let type_specs = vec![TypeSpecification {
            token: token(27, 1),
            signature: type_signature,
        }];

        project_member_reference_parents(&mut references, &[], &[], &type_specs);

        assert_eq!(
            references[0].parent_name.as_deref(),
            Some("Example.Worker[]")
        );
    }

    #[test]
    fn extracts_assembly_target_framework_attribute_values() {
        let attributes = vec![CustomAttribute {
            token: token(12, 1),
            source_offset: Some(12),
            parent_token: Some(token(32, 1)),
            constructor_token: Some(token(10, 1)),
            blob_offset: 1,
            blob_hex: None,
            value_length: 0,
            value_sha256: digest(&[]),
            decoded_fixed_string: Some(".NETCoreApp,Version=v8.0".to_owned()),
            serialized_prolog: Some(1),
            serialized_named_argument_count: Some(0),
            serialized_shape_issue: None,
            issue: None,
        }];
        let member_references = vec![MemberReference {
            token: token(10, 1),
            row_offset: Some(20),
            name: ".ctor".to_owned(),
            parent_token: Some(token(1, 1)),
            parent_name: Some("System.Runtime.Versioning.TargetFrameworkAttribute".to_owned()),
            signature: signature(),
        }];

        assert_eq!(
            target_frameworks(&attributes, &member_references),
            vec![".NETCoreApp,Version=v8.0"]
        );
    }

    #[test]
    fn classifies_runtime_family_from_cli_framework_and_unity_facts() {
        assert_eq!(runtime_family(&[], &[], 0), "mixed-clr-native");
        assert_eq!(
            runtime_family(&[".NETFramework,Version=v4.8".to_owned()], &[], 1),
            "dotnet-framework"
        );
        assert_eq!(
            runtime_family(&[".NETCoreApp,Version=v8.0".to_owned()], &[], 1),
            "modern-dotnet"
        );
        assert_eq!(
            runtime_family(
                &[],
                &[AssemblyReference {
                    name: "UnityEngine.CoreModule".to_owned(),
                    version: String::new(),
                    culture: None,
                    flags: 0,
                    token: token(35, 1),
                    public_key_or_token_offset: None,
                    public_key_or_token_hex: None,
                    hash_value_offset: None,
                    hash_value_hex: None,
                    issue: None,
                }],
                1,
            ),
            "unity-mono"
        );
    }

    #[test]
    fn normalizes_decoded_il_anchors_without_offsets() {
        let first = vec![InstructionAnchor {
            il_offset: 0,
            opcode: "0x28".to_owned(),
            operand_kind: "method",
            operand: Some("0x06000001".to_owned()),
            user_string: None,
            user_string_offset: None,
            user_string_issue: None,
        }];
        let second = vec![InstructionAnchor {
            il_offset: 99,
            opcode: "0x28".to_owned(),
            operand_kind: "method",
            operand: Some("0x06000001".to_owned()),
            user_string: None,
            user_string_offset: None,
            user_string_issue: None,
        }];

        assert_eq!(normalized_il_digest(&first), normalized_il_digest(&second));
    }

    #[test]
    fn decodes_short_and_long_branch_targets_as_il_offsets() {
        assert_eq!(token_operand_kind(0x2b), "branch");
        assert_eq!(
            branch_target(4, 0x2b, 1, Some(&[0x02])),
            Some("0x00000008".to_owned())
        );
        assert_eq!(
            branch_target(8, 0x38, 4, Some(&[0xfc, 0xff, 0xff, 0xff])),
            Some("0x00000009".to_owned())
        );
    }

    #[test]
    fn classifies_switch_operands_and_reads_target_count() {
        assert_eq!(token_operand_kind(0x45), "switch");
        assert_eq!(operand_length(0x45, &[2, 0, 0, 0]), 12);
        assert_eq!(
            switch_operand_count(Some(&[2, 0, 0, 0])),
            Some("2".to_owned())
        );
        assert_eq!(switch_operand_count(Some(&[1, 0])), None);

        assert_eq!(
            switch_operand_length(&[0xff, 0xff, 0xff, 0xff]),
            Some(17_179_869_184)
        );
    }

    #[test]
    fn decodes_cil_constant_and_variable_operands() {
        assert_eq!(token_operand_kind(0x1f), "constant");
        assert_eq!(literal_operand(0x1f, Some(&[0xfe])), Some("-2".to_owned()));
        assert_eq!(
            literal_operand(0x20, Some(&[2, 0, 0, 0])),
            Some("2".to_owned())
        );
        assert_eq!(
            literal_operand(0x21, Some(&[2, 0, 0, 0, 0, 0, 0, 0])),
            Some("2".to_owned())
        );
        assert_eq!(token_operand_kind(0x11), "variable");
        assert_eq!(
            variable_or_literal_operand(0x11, Some(&[7])),
            Some("7".to_owned())
        );
    }

    #[test]
    fn classifies_calli_as_a_standalone_signature_operand() {
        assert_eq!(token_operand_kind(0x29), "signature");
        assert_eq!(operand_length(0x29, &[]), 4);
    }

    #[test]
    fn decodes_prefixed_cil_operand_widths_and_kinds() {
        assert_eq!(extended_operand_length(0x0c, &[]), 2);
        assert_eq!(
            prefixed_operand_value(Some(0x0c), Some(&[7, 0])),
            Some("7".to_owned())
        );
        assert_eq!(operand_kind(0xfe, Some(0x0c)), "variable");
        assert_eq!(extended_operand_length(0x16, &[]), 4);
        assert_eq!(operand_kind(0xfe, Some(0x16)), "type");
        assert_eq!(extended_operand_length(0x19, &[]), 1);
    }

    #[test]
    fn decodes_multidimensional_and_generic_instance_types() {
        let mut array_at = 0;
        assert_eq!(
            decode_type(&[0x14, 0x08, 0x02, 0x00, 0x00, 0x00], &mut array_at),
            Some("int32[,]".to_owned())
        );

        let mut generic_at = 0;
        assert_eq!(
            decode_type(&[0x15, 0x12, 0x04, 0x01, 0x0e], &mut generic_at),
            Some("token:0x00000004<string>".to_owned())
        );
        let mut malformed_at = 0;
        assert_eq!(decode_type(&[0x14, 0x08, 0x00], &mut malformed_at), None);
    }

    #[test]
    fn validates_exception_section_kind_bounds_and_reserved_bytes() {
        let mut section = vec![0x01, 16, 0, 0];
        section.extend_from_slice(&[0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0]);
        let regions = exception_regions(&section, 0, 2).expect("valid small clause");
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].try_length, 1);
        assert_eq!(regions[0].handler_offset, 1);

        let mut wrong_kind = section.clone();
        wrong_kind[0] = 2;
        assert!(exception_regions(&wrong_kind, 0, 2).is_err());

        let mut bad_reserved = section.clone();
        bad_reserved[2] = 1;
        assert!(exception_regions(&bad_reserved, 0, 2).is_err());

        let truncated = &section[..section.len() - 1];
        assert!(exception_regions(truncated, 0, 2).is_err());
    }

    #[test]
    fn decodes_type_ref_resolution_scope() {
        let mut rows = vec![0; 64];
        rows[1] = 1;
        rows[35] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 1) | (1u64 << 35),
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'T', b'\0', b'N', b'\0'],
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 40];
        bytes[32..34].copy_from_slice(&1u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&3u16.to_le_bytes());
        bytes[36..38].copy_from_slice(&(1u16 << 2 | 3).to_le_bytes());

        let references = root.type_references(&bytes);

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].name, "T");
        assert_eq!(references[0].namespace, "N");
        assert_eq!(references[0].raw_resolution_scope, Some(7));
        assert_eq!(references[0].resolution_scope_kind, Some("AssemblyRef"));
        assert_eq!(references[0].resolution_scope_token, Some(token(35, 1)));
        assert_eq!(references[0].issue, None);
    }

    #[test]
    fn preserves_module_edit_and_source_identity() {
        let mut rows = vec![0; 64];
        rows[0] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1,
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'M', b'o', b'd', b'u', b'l', b'e', b'\0'],
            guids: (1..=48).collect(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 38];
        let row = table_start(root.tables.as_ref().expect("module table"), 0);
        bytes[row..row + 2].copy_from_slice(&7u16.to_le_bytes());
        bytes[row + 2..row + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[row + 4..row + 6].copy_from_slice(&1u16.to_le_bytes());
        bytes[row + 6..row + 8].copy_from_slice(&2u16.to_le_bytes());
        bytes[row + 8..row + 10].copy_from_slice(&3u16.to_le_bytes());

        let pe = PeLayout {
            machine: 0,
            characteristics: 0,
            headers: 0,
            cli_rva: 0,
            sections: Vec::new(),
            debug_rva: 0,
            debug_size: 0,
        };
        let module = root.module(&bytes, &pe).expect("module row");

        assert_eq!(module.row_offset, Some(row));
        assert_eq!(module.name, "Module");
        assert_eq!(module.generation, 7);
        assert_eq!(
            module.mvid,
            Some("04030201-0605-0807-090a-0b0c0d0e0f10".into())
        );
        assert_eq!(
            module.enc_id,
            Some("14131211-1615-1817-191a-1b1c1d1e1f20".into())
        );
        assert_eq!(
            module.enc_base_id,
            Some("24232221-2625-2827-292a-2b2c2d2e2f30".into())
        );
    }

    #[test]
    fn decodes_exported_types_and_retains_invalid_implementation_rows() {
        let mut rows = vec![0; 64];
        rows[39] = 2;
        rows[35] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 39,
                rows,
                heap_sizes: 0,
            }),
            strings: vec![
                0, b'E', b'x', b'p', b'o', b'r', b't', b'\0', b'N', b's', b'\0',
            ],
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 28 + 2 * 14];

        bytes[28..32].copy_from_slice(&0x0020_0000u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&7u32.to_le_bytes());
        bytes[36..38].copy_from_slice(&1u16.to_le_bytes());
        bytes[38..40].copy_from_slice(&8u16.to_le_bytes());
        bytes[40..42].copy_from_slice(&((1u16 << 2) | 1).to_le_bytes());

        bytes[42..46].copy_from_slice(&0u32.to_le_bytes());
        bytes[46..50].copy_from_slice(&9u32.to_le_bytes());
        bytes[50..52].copy_from_slice(&3u16.to_le_bytes());
        bytes[52..54].copy_from_slice(&0u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&0x0fu16.to_le_bytes());

        let exported = root.exported_types(&bytes);

        assert_eq!(exported.len(), 2);
        assert_eq!(exported[0].token, token(39, 1));
        assert_eq!(exported[0].name, "Export");
        assert_eq!(exported[0].namespace, "Ns");
        assert!(exported[0].forwarder);
        assert_eq!(exported[0].type_def_id, 7);
        assert_eq!(exported[0].implementation_kind, "assembly-ref");
        assert_eq!(exported[0].implementation_token, Some(token(35, 1)));
        assert_eq!(exported[0].issue, None);
        assert_eq!(exported[1].implementation_token, None);
        assert_eq!(exported[1].implementation_kind, "unknown");
        assert_eq!(
            exported[1].issue.as_deref(),
            Some("ExportedType implementation coded index has an invalid tag")
        );
    }

    #[test]
    fn decodes_field_rva_and_preserves_data_bytes() {
        let mut rows = vec![0; 64];
        rows[4] = 1;
        rows[29] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 4) | (1u64 << 29),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 44];
        bytes[38..42].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[42..44].copy_from_slice(&1u16.to_le_bytes());
        let mut field_rvas = root.field_rvas(&bytes);
        let pe = PeLayout {
            machine: 0,
            characteristics: 0,
            headers: 0x200,
            cli_rva: 0,
            sections: vec![Section {
                va: 0x2000,
                raw: 0,
                size: 4,
            }],
            debug_rva: 0,
            debug_size: 0,
        };
        let data = [0xde, 0xad, 0xbe, 0xef];
        project_field_rva_data(&mut field_rvas, &pe, &data);

        assert_eq!(field_rvas[0].field_token, Some(token(4, 1)));
        assert_eq!(field_rvas[0].rva, Some(0x2000));
        assert_eq!(field_rvas[0].data_offset, Some(0));
        assert_eq!(field_rvas[0].data_hex, Some("deadbeef".to_owned()));
        assert_eq!(field_rvas[0].issue, None);
    }

    #[test]
    fn decodes_field_layout_offsets_and_ownership() {
        let mut rows = vec![0; 64];
        rows[4] = 1;
        rows[16] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 4) | (1u64 << 16),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 44];
        bytes[38..42].copy_from_slice(&0x24u32.to_le_bytes());
        bytes[42..44].copy_from_slice(&1u16.to_le_bytes());

        let layouts = root.field_layouts(&bytes);

        assert_eq!(layouts[0].token, token(16, 1));
        assert_eq!(layouts[0].field_token, Some(token(4, 1)));
        assert_eq!(layouts[0].offset, Some(0x24));
        assert_eq!(layouts[0].issue, None);
    }

    #[test]
    fn decodes_class_layout_parent_and_sizes() {
        let mut rows = vec![0; 64];
        rows[2] = 1;
        rows[15] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 2) | (1u64 << 15),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 54];
        bytes[46..48].copy_from_slice(&4u16.to_le_bytes());
        bytes[48..52].copy_from_slice(&0x30u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&1u16.to_le_bytes());

        let layouts = root.class_layouts(&bytes);

        assert_eq!(layouts[0].token, token(15, 1));
        assert_eq!(layouts[0].source_offset, Some(46));
        assert_eq!(layouts[0].packing_size, Some(4));
        assert_eq!(layouts[0].class_size, Some(0x30));
        assert_eq!(layouts[0].parent_type_token, Some(token(2, 1)));
        assert_eq!(layouts[0].issue, None);
    }

    #[test]
    fn preserves_invalid_class_layout_packing() {
        let mut rows = vec![0; 64];
        rows[2] = 1;
        rows[15] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 2) | (1u64 << 15),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 54];
        bytes[46..48].copy_from_slice(&3u16.to_le_bytes());
        bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&1u16.to_le_bytes());

        let layouts = root.class_layouts(&bytes);

        assert_eq!(layouts[0].parent_type_token, Some(token(2, 1)));
        assert_eq!(
            layouts[0].issue.as_deref(),
            Some("ClassLayout packing size is invalid")
        );
    }

    #[test]
    fn decodes_assembly_processor_value() {
        let mut rows = vec![0; 64];
        rows[33] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 33,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 32];
        bytes[28..32].copy_from_slice(&0x8664u32.to_le_bytes());

        let processors = root.assembly_processors(&bytes);

        assert_eq!(processors[0].token, token(33, 1));
        assert_eq!(processors[0].source_offset, Some(28));
        assert_eq!(processors[0].processor, Some(0x8664));
        assert_eq!(processors[0].issue, None);
    }

    #[test]
    fn preserves_truncated_assembly_processor_row() {
        let mut rows = vec![0; 64];
        rows[33] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 33,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };

        let processors = root.assembly_processors(&[0, 1]);

        assert_eq!(processors[0].processor, None);
        assert_eq!(
            processors[0].issue.as_deref(),
            Some("truncated AssemblyProcessor row")
        );
    }

    #[test]
    fn decodes_assembly_os_identity() {
        let mut rows = vec![0; 64];
        rows[34] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 34,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 40];
        bytes[28..32].copy_from_slice(&4u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&10u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&2u32.to_le_bytes());

        let os_rows = root.assembly_os(&bytes);

        assert_eq!(os_rows[0].token, token(34, 1));
        assert_eq!(os_rows[0].source_offset, Some(28));
        assert_eq!(os_rows[0].platform_id, Some(4));
        assert_eq!(os_rows[0].major_version, Some(10));
        assert_eq!(os_rows[0].minor_version, Some(2));
        assert_eq!(os_rows[0].issue, None);
    }

    #[test]
    fn preserves_truncated_assembly_os_row() {
        let mut rows = vec![0; 64];
        rows[34] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 34,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };

        let os_rows = root.assembly_os(&[0; 8]);

        assert_eq!(os_rows[0].platform_id, None);
        assert_eq!(os_rows[0].major_version, None);
        assert_eq!(os_rows[0].minor_version, None);
        assert_eq!(
            os_rows[0].issue.as_deref(),
            Some("truncated AssemblyOS row")
        );
    }

    #[test]
    fn decodes_assembly_ref_processor_owner() {
        let mut rows = vec![0; 64];
        rows[35] = 1;
        rows[36] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 35) | (1u64 << 36),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 58];
        bytes[52..56].copy_from_slice(&0x8664u32.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let processors = root.assembly_ref_processors(&bytes);

        assert_eq!(processors[0].token, token(36, 1));
        assert_eq!(processors[0].source_offset, Some(52));
        assert_eq!(processors[0].processor, Some(0x8664));
        assert_eq!(processors[0].assembly_ref_token, Some(token(35, 1)));
        assert_eq!(processors[0].issue, None);
    }

    #[test]
    fn preserves_invalid_assembly_ref_processor_owner() {
        let mut rows = vec![0; 64];
        rows[36] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 36,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 34];
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&1u16.to_le_bytes());

        let processors = root.assembly_ref_processors(&bytes);

        assert_eq!(processors[0].assembly_ref_token, None);
        assert_eq!(
            processors[0].issue.as_deref(),
            Some("AssemblyRefProcessor assembly reference is out of range")
        );
    }

    #[test]
    fn decodes_assembly_ref_os_owner_and_versions() {
        let mut rows = vec![0; 64];
        rows[35] = 1;
        rows[37] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 35) | (1u64 << 37),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 66];
        bytes[52..56].copy_from_slice(&4u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&10u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&2u32.to_le_bytes());
        bytes[64..66].copy_from_slice(&1u16.to_le_bytes());

        let os_rows = root.assembly_ref_os(&bytes);

        assert_eq!(os_rows[0].token, token(37, 1));
        assert_eq!(os_rows[0].source_offset, Some(52));
        assert_eq!(os_rows[0].platform_id, Some(4));
        assert_eq!(os_rows[0].major_version, Some(10));
        assert_eq!(os_rows[0].minor_version, Some(2));
        assert_eq!(os_rows[0].assembly_ref_token, Some(token(35, 1)));
        assert_eq!(os_rows[0].issue, None);
    }

    #[test]
    fn preserves_invalid_assembly_ref_os_owner() {
        let mut rows = vec![0; 64];
        rows[37] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 37,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };

        let os_rows = root.assembly_ref_os(&[0; 42]);

        assert_eq!(os_rows[0].assembly_ref_token, None);
        assert_eq!(
            os_rows[0].issue.as_deref(),
            Some("AssemblyRefOS assembly reference is out of range")
        );
    }

    #[test]
    fn decodes_file_name_flags_and_hash() {
        let mut rows = vec![0; 64];
        rows[38] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 38,
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'f', b'i', b'l', b'e', b'.', b'd', b'l', b'l', 0],
            guids: Vec::new(),
            blobs: vec![0, 2, 0xaa, 0xbb],
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 36];
        bytes[28..32].copy_from_slice(&0x2u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&1u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&1u16.to_le_bytes());

        let files = root.files(&bytes);

        assert_eq!(files[0].token, token(38, 1));
        assert_eq!(files[0].source_offset, Some(28));
        assert_eq!(files[0].flags, Some(2));
        assert_eq!(files[0].contains_metadata, Some(false));
        assert_eq!(files[0].name_offset, Some(1));
        assert_eq!(files[0].name.as_deref(), Some("file.dll"));
        assert_eq!(files[0].hash_blob_offset, Some(1));
        assert_eq!(files[0].hash_blob_hex, Some("aabb".to_owned()));
        assert_eq!(files[0].hash_blob_sha256, Some(digest(&[0xaa, 0xbb])));
        assert_eq!(files[0].issue, None);
    }

    #[test]
    fn preserves_file_hash_heap_failure() {
        let mut rows = vec![0; 64];
        rows[38] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 38,
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'f', 0],
            guids: Vec::new(),
            blobs: vec![0, 1, 0xaa],
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 36];
        bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&1u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&9u16.to_le_bytes());

        let files = root.files(&bytes);

        assert_eq!(files[0].name.as_deref(), Some("f"));
        assert_eq!(files[0].hash_blob_offset, Some(9));
        assert_eq!(
            files[0].issue.as_deref(),
            Some("File hash blob is outside #Blob")
        );
    }

    #[test]
    fn projects_manifest_resource_visibility_and_embedded_state() {
        let mut rows = vec![0; 64];
        rows[40] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 40,
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'r', b'.', b'd', b'l', b'l', 0],
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 40];
        bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[36..38].copy_from_slice(&1u16.to_le_bytes());
        bytes[38..40].copy_from_slice(&0u16.to_le_bytes());

        let resources = root.manifest_resources(&bytes, Some(&[3, 0, 0, 0, 1, 2, 3]), Some(100));

        assert_eq!(resources[0].visibility, "public");
        assert!(resources[0].embedded);
        assert_eq!(resources[0].implementation_kind, "embedded");
        assert_eq!(resources[0].size, Some(3));
        assert_eq!(resources[0].bytes_hex, Some("010203".to_owned()));
        assert_eq!(resources[0].data_sha256, Some(digest(&[1, 2, 3])));
        assert_eq!(resources[0].issue, None);
    }

    #[test]
    fn preserves_unknown_manifest_resource_visibility_bits() {
        let mut rows = vec![0; 64];
        rows[40] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 40,
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'r', 0],
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 40];
        bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&3u32.to_le_bytes());
        bytes[36..38].copy_from_slice(&1u16.to_le_bytes());
        bytes[38..40].copy_from_slice(&0u16.to_le_bytes());

        let resources = root.manifest_resources(&bytes, Some(&[0, 0, 0, 0]), Some(100));

        assert_eq!(resources[0].visibility, "unknown");
        assert!(resources[0].embedded);
        assert_eq!(resources[0].implementation_kind, "embedded");
    }

    #[test]
    fn decodes_impl_map_member_and_module_tokens() {
        let mut rows = vec![0; 64];
        rows[4] = 1;
        rows[6] = 1;
        rows[26] = 1;
        rows[28] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 4) | (1u64 << 6) | (1u64 << 26) | (1u64 << 28),
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'P', 0],
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 70];
        bytes[62..64].copy_from_slice(&0x1u16.to_le_bytes());
        bytes[64..66].copy_from_slice(&((1u16 << 1) | 1).to_le_bytes());
        bytes[66..68].copy_from_slice(&1u16.to_le_bytes());
        bytes[68..70].copy_from_slice(&1u16.to_le_bytes());

        let maps = root.impl_maps(&bytes);

        assert_eq!(maps[0].source_offset, Some(62));
        assert_eq!(maps[0].member_token, Some(token(6, 1)));
        assert_eq!(maps[0].module_token, Some(token(26, 1)));
        assert_eq!(maps[0].import_name, "P");
        assert_eq!(maps[0].flag_names, vec!["no-mangle"]);
        assert_eq!(maps[0].unknown_flags, 0);
        assert_eq!(maps[0].issue, None);
    }

    #[test]
    fn preserves_invalid_impl_map_member_and_module_references() {
        let mut rows = vec![0; 64];
        rows[28] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 28,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 36];
        bytes[28..30].copy_from_slice(&0x8001u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&0u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&0u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&0u16.to_le_bytes());

        let maps = root.impl_maps(&bytes);

        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].raw_member_forwarded, Some(0));
        assert_eq!(maps[0].module_token, None);
        assert_eq!(maps[0].unknown_flags, 0x8000);
        assert_eq!(
            maps[0].issue.as_deref(),
            Some("ImplMap member reference is out of range")
        );
    }

    #[test]
    fn decodes_method_impl_code_and_unknown_flags() {
        let (code, managed, names, unknown) =
            decode_method_impl_flags(0x1000 | 0x0080 | 0x0004 | 0x8000);
        assert_eq!(code, "il");
        assert_eq!(managed, "managed");
        assert_eq!(names, vec!["preserve-signature", "internal-call"]);
        assert_eq!(unknown, 0x8000);

        let (code, managed, names, unknown) = decode_method_impl_flags(0x0005);
        assert_eq!(code, "native");
        assert_eq!(managed, "managed");
        assert!(names.is_empty());
        assert_eq!(unknown, 0);
    }

    #[test]
    fn decodes_custom_attribute_parent_constructor_blob_and_source() {
        let mut rows = vec![0; 45];
        rows[12] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 12,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: vec![0, 3, 1, 2, 3],
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 34];
        bytes[28..30].copy_from_slice(&34u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&10u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&1u16.to_le_bytes());

        let attributes = root.custom_attributes(&bytes);

        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].source_offset, Some(28));
        assert_eq!(attributes[0].parent_token, Some(token(2, 1)));
        assert_eq!(attributes[0].constructor_token, Some(token(6, 1)));
        assert_eq!(attributes[0].blob_offset, 1);
        assert_eq!(attributes[0].blob_hex, Some("010203".to_owned()));
        assert_eq!(attributes[0].issue, None);
    }

    #[test]
    fn preserves_null_custom_attribute_coded_indices_as_issues() {
        let mut rows = vec![0; 45];
        rows[12] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 12,
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: vec![0],
            user_strings: Vec::new(),
        };
        let attributes = root.custom_attributes(&vec![0; 34]);

        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].parent_token, None);
        assert_eq!(attributes[0].constructor_token, None);
        assert_eq!(
            attributes[0].issue.as_deref(),
            Some("CustomAttribute parent coded index 0x0 is null")
        );
    }

    #[test]
    fn decodes_param_sequence_name_and_truncated_state() {
        let mut rows = vec![0; 14];
        rows[8] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 8,
                rows,
                heap_sizes: 0,
            }),
            strings: vec![0, b'p', 0],
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 34];
        bytes[28..30].copy_from_slice(&0x0010u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&0u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&1u16.to_le_bytes());

        let params = root.params(&bytes);

        assert_eq!(params[0].source_offset, Some(28));
        assert_eq!(params[0].flags, 0x0010);
        assert_eq!(params[0].sequence, 0);
        assert_eq!(params[0].name, "p");
        assert_eq!(params[0].issue, None);

        let truncated = root.params(&bytes[..32]);
        assert_eq!(truncated[0].issue.as_deref(), Some("truncated Param row"));
    }

    #[test]
    fn decodes_field_marshal_native_type_and_source_blob() {
        let mut rows = vec![0; 64];
        rows[4] = 1;
        rows[13] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 4) | (1u64 << 13),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: vec![0, 1, 0x14],
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 42];
        bytes[38..40].copy_from_slice(&2u16.to_le_bytes());
        bytes[40..42].copy_from_slice(&1u16.to_le_bytes());

        let marshals = root.field_marshals(&bytes);

        assert_eq!(marshals.len(), 1);
        assert_eq!(marshals[0].source_offset, Some(38));
        assert_eq!(marshals[0].parent_token, Some(token(4, 1)));
        assert_eq!(marshals[0].native_type_blob_offset, 1);
        assert_eq!(marshals[0].native_type_blob_hex, Some("14".to_owned()));
        assert_eq!(marshals[0].decoded_native_type, Some("lpstr"));
        assert_eq!(marshals[0].issue, None);
    }

    #[test]
    fn preserves_unsupported_field_marshal_native_type_as_issue() {
        let mut rows = vec![0; 64];
        rows[4] = 1;
        rows[13] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 4) | (1u64 << 13),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: vec![0, 1, 0xff],
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 42];
        bytes[38..40].copy_from_slice(&2u16.to_le_bytes());
        bytes[40..42].copy_from_slice(&1u16.to_le_bytes());

        let marshals = root.field_marshals(&bytes);

        assert_eq!(marshals.len(), 1);
        assert_eq!(marshals[0].native_type_blob_hex, Some("ff".to_owned()));
        assert_eq!(marshals[0].decoded_native_type, None);
        assert_eq!(
            marshals[0].issue.as_deref(),
            Some("FieldMarshal native type is unsupported or malformed")
        );
    }

    #[test]
    fn decodes_decl_security_owner_and_permission_blob() {
        let mut rows = vec![0; 64];
        rows[14] = 1;
        rows[32] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 14) | (1u64 << 32),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: vec![0, 2, 0xaa, 0xbb],
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 38];
        bytes[32..34].copy_from_slice(&2u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&6u16.to_le_bytes());
        bytes[36..38].copy_from_slice(&1u16.to_le_bytes());

        let rows = root.decl_security(&bytes);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source_offset, Some(32));
        assert_eq!(rows[0].action, Some(2));
        assert_eq!(rows[0].parent_token, Some(token(32, 1)));
        assert_eq!(rows[0].permission_blob_offset, 1);
        assert_eq!(rows[0].permission_blob_hex, Some("aabb".to_owned()));
        assert_eq!(rows[0].issue, None);
    }

    #[test]
    fn preserves_invalid_decl_security_owner_as_issue() {
        let mut table_rows = vec![0; 64];
        table_rows[14] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: 1u64 << 14,
                rows: table_rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: vec![0, 1, 0x01],
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 34];
        bytes[28..30].copy_from_slice(&1u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&3u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&1u16.to_le_bytes());

        let rows = root.decl_security(&bytes);

        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].issue.as_deref(),
            Some("DeclSecurity parent coded index has an invalid tag")
        );
    }

    #[test]
    fn projects_nested_class_ownership() {
        let mut types = (1..=3)
            .map(|row| TypeDefinition {
                token: token(2, row),
                row_offset: Some(row as usize),
                name: format!("Type{row}"),
                namespace: "Example".to_owned(),
                full_name: format!("Example.Type{row}"),
                name_sha256: None,
                flags: 0,
                extends_token: None,
                field_list: test_member_list(1),
                method_list: test_member_list(1),
                custom_attributes: Vec::new(),
                interface_impl_tokens: Vec::new(),
                method_impl_tokens: Vec::new(),
                enclosing_type_token: None,
                nested_type_tokens: Vec::new(),
            })
            .collect::<Vec<_>>();
        let nested_classes = vec![NestedClass {
            token: token(41, 1),
            source_offset: Some(128),
            nested_type_token: Some(token(2, 2)),
            enclosing_type_token: Some(token(2, 1)),
            issue: None,
        }];

        project_nested_classes(&mut types, &nested_classes);

        assert_eq!(types[1].enclosing_type_token, Some(token(2, 1)));
        assert_eq!(types[0].nested_type_tokens, vec![token(2, 2)]);
    }

    #[test]
    fn projects_typescript_compatible_nominal_name_digests() {
        let mut types = vec![
            TypeDefinition {
                token: token(2, 1),
                row_offset: Some(1),
                name: "Outer".to_owned(),
                namespace: "Example".to_owned(),
                full_name: String::new(),
                name_sha256: None,
                flags: 0,
                extends_token: None,
                field_list: test_member_list(1),
                method_list: test_member_list(1),
                custom_attributes: Vec::new(),
                interface_impl_tokens: Vec::new(),
                method_impl_tokens: Vec::new(),
                enclosing_type_token: None,
                nested_type_tokens: vec![token(2, 2)],
            },
            TypeDefinition {
                token: token(2, 2),
                row_offset: Some(2),
                name: "Nested".to_owned(),
                namespace: String::new(),
                full_name: String::new(),
                name_sha256: None,
                flags: 0,
                extends_token: None,
                field_list: test_member_list(1),
                method_list: test_member_list(1),
                custom_attributes: Vec::new(),
                interface_impl_tokens: Vec::new(),
                method_impl_tokens: Vec::new(),
                enclosing_type_token: Some(token(2, 1)),
                nested_type_tokens: Vec::new(),
            },
        ];

        project_type_full_names(&mut types);
        project_type_name_digests(&mut types);

        assert_eq!(types[0].full_name, "Example.Outer");
        assert_eq!(types[1].full_name, "Outer.Nested");
        assert_eq!(
            types[0].name_sha256.as_deref(),
            Some("99421c21ed8b84b9918380d070f9f52f560fcbbbe3c78c54c9d6897564854027")
        );
        assert_eq!(
            types[1].name_sha256.as_deref(),
            Some("d480e2c54260384abb65069ed0a71612afaea0896f84b539aade74785484179e")
        );
    }

    #[test]
    fn projects_type_member_ranges_with_final_table_bounds() {
        let mut types = (1..=2)
            .map(|row| TypeDefinition {
                token: token(2, row),
                row_offset: Some(row as usize),
                name: format!("Type{row}"),
                namespace: String::new(),
                full_name: format!("Type{row}"),
                name_sha256: None,
                flags: 0,
                extends_token: None,
                field_list: test_member_list(if row == 1 { 1 } else { 3 }),
                method_list: test_member_list(if row == 1 { 2 } else { 3 }),
                custom_attributes: Vec::new(),
                interface_impl_tokens: Vec::new(),
                method_impl_tokens: Vec::new(),
                enclosing_type_token: None,
                nested_type_tokens: Vec::new(),
            })
            .collect::<Vec<_>>();

        project_member_list_ranges(&mut types, 3, 4);

        assert_eq!(types[0].field_list.first_row, Some(1));
        assert_eq!(types[0].field_list.last_row, Some(2));
        assert_eq!(types[0].field_list.count, 2);
        assert_eq!(types[1].field_list.last_row, Some(3));
        assert_eq!(types[1].field_list.count, 1);
        assert_eq!(types[0].method_list.last_row, Some(2));
        assert_eq!(types[1].method_list.last_row, Some(4));
    }

    #[test]
    fn selects_managed_members_by_exact_declaring_type() {
        let types = vec![
            TypeDefinition {
                token: token(2, 1),
                row_offset: Some(10),
                name: "Outer".to_owned(),
                namespace: "Example".to_owned(),
                full_name: "Example.Outer".to_owned(),
                name_sha256: None,
                flags: 0,
                extends_token: None,
                field_list: test_member_list(1),
                method_list: test_member_list(1),
                custom_attributes: Vec::new(),
                interface_impl_tokens: Vec::new(),
                method_impl_tokens: Vec::new(),
                enclosing_type_token: None,
                nested_type_tokens: Vec::new(),
            },
            TypeDefinition {
                token: token(2, 2),
                row_offset: Some(20),
                name: "Nested".to_owned(),
                namespace: "Example".to_owned(),
                full_name: "Example.Nested".to_owned(),
                name_sha256: None,
                flags: 0,
                extends_token: None,
                field_list: test_member_list(2),
                method_list: test_member_list(1),
                custom_attributes: Vec::new(),
                interface_impl_tokens: Vec::new(),
                method_impl_tokens: Vec::new(),
                enclosing_type_token: Some(token(2, 1)),
                nested_type_tokens: Vec::new(),
            },
        ];
        let fields = vec![
            FieldDefinition {
                token: token(4, 1),
                source_offset: Some(40),
                declaring_type_token: Some(token(2, 1)),
                declaring_type: Some("Example.Outer".to_owned()),
                name: "outerField".to_owned(),
                flags: 0,
                signature: signature(),
                constants: Vec::new(),
                rva: None,
                data_offset: None,
                data_hex: None,
                layout_offset: None,
                custom_attributes: vec![CustomAttribute {
                    token: token(12, 1),
                    source_offset: Some(28),
                    parent_token: Some(token(4, 1)),
                    constructor_token: Some(token(6, 1)),
                    blob_offset: 1,
                    blob_hex: Some("010203".to_owned()),
                    value_length: 3,
                    value_sha256: digest(&[1, 2, 3]),
                    decoded_fixed_string: None,
                    serialized_prolog: None,
                    serialized_named_argument_count: None,
                    serialized_shape_issue: None,
                    issue: None,
                }],
                issue: None,
            },
            FieldDefinition {
                token: token(4, 2),
                source_offset: Some(48),
                declaring_type_token: Some(token(2, 2)),
                declaring_type: Some("Example.Inner".to_owned()),
                name: "nestedField".to_owned(),
                flags: 0,
                signature: signature(),
                constants: Vec::new(),
                rva: None,
                data_offset: None,
                data_hex: None,
                layout_offset: None,
                custom_attributes: Vec::new(),
                issue: None,
            },
        ];
        let inspection = Inspection {
            artifact: Artifact {
                byte_length: 0,
                format: "pe",
            },
            pe: Pe {
                machine: 0,
                machine_hex: String::new(),
                architecture: "unknown",
                section_count: 0,
                characteristics: 0,
                cli: None,
            },
            debug: None,
            classification: Classification {
                status: "managed",
                runtime_family: "unknown",
                implementation: "cil",
                managed_architecture: "unknown",
            },
            metadata: Metadata {
                status: "present",
                version: None,
                stream_names: Vec::new(),
                table_row_counts: std::collections::BTreeMap::new(),
            },
            module: Some(Module {
                row_offset: None,
                name: "module.dll".to_owned(),
                generation: 0,
                mvid: Some("mvid".to_owned()),
                enc_id: None,
                enc_base_id: None,
                token: token(0, 1),
            }),
            assembly: Some(Assembly {
                row_offset: None,
                name: "Example".to_owned(),
                version: "1.2.3.4".to_owned(),
                culture: None,
                flags: 0,
                hash_algorithm: 0,
                public_key_offset: Some(0),
                public_key_kind: "none",
                public_key_byte_length: 0,
                public_key_sha256: None,
                public_key_token: None,
                token: token(32, 1),
                custom_attributes: Vec::new(),
            }),
            assembly_processors: Vec::new(),
            assembly_os: Vec::new(),
            assembly_ref_processors: Vec::new(),
            assembly_ref_os: Vec::new(),
            files: Vec::new(),
            references: vec![AssemblyReference {
                name: "Dependency".to_owned(),
                version: "1.0.0.0".to_owned(),
                culture: None,
                flags: 0,
                token: token(35, 1),
                public_key_or_token_offset: None,
                public_key_or_token_hex: None,
                hash_value_offset: None,
                hash_value_hex: None,
                issue: None,
            }],
            module_references: vec![ModuleReference {
                source_offset: Some(64),
                name: "native.dll".to_owned(),
                token: token(26, 1),
                issue: None,
            }],
            impl_maps: Vec::new(),
            type_references: Vec::new(),
            types,
            fields,
            field_rvas: Vec::new(),
            field_layouts: Vec::new(),
            field_marshals: Vec::new(),
            decl_security: Vec::new(),
            class_layouts: Vec::new(),
            methods: Vec::new(),
            member_references: Vec::new(),
            params: Vec::new(),
            generic_params: vec![GenericParameter {
                token: token(42, 1),
                source_offset: Some(128),
                number: 0,
                flags: 0x0001 | 0x0004,
                owner_token: token(2, 1),
                name: "T".to_owned(),
                variance: Some("covariant"),
                special_constraints: vec!["reference-type"],
                unknown_flags: 0,
                issue: None,
            }],
            generic_constraints: vec![GenericParameterConstraint {
                token: token(44, 1),
                source_offset: Some(144),
                owner_token: token(42, 1),
                constraint_token: token(2, 1),
                constraint_kind: "type-def",
                issue: None,
            }],
            type_specs: Vec::new(),
            method_specs: Vec::new(),
            standalone_signatures: Vec::new(),
            property_maps: Vec::new(),
            properties: Vec::new(),
            method_semantics: Vec::new(),
            event_maps: Vec::new(),
            events: Vec::new(),
            interface_impls: Vec::new(),
            method_impls: Vec::new(),
            custom_attributes: Vec::new(),
            constants: Vec::new(),
            manifest_resources: Vec::new(),
            exported_types: Vec::new(),
            target_frameworks: Vec::new(),
            nested_classes: Vec::new(),
            coverage: Coverage {
                state: "complete",
                issues: Vec::new(),
            },
            limitations: Vec::new(),
        };
        let selected = inspect_managed_members(
            &inspection,
            Some(&["Example.Outer".to_owned(), "Missing".to_owned()]),
        );

        assert_eq!(selected.types.len(), 1);
        assert_eq!(
            selected.module.as_ref().map(|module| module.name.as_str()),
            Some("module.dll")
        );
        assert_eq!(
            selected
                .assembly
                .as_ref()
                .map(|assembly| assembly.name.as_str()),
            Some("Example")
        );
        assert_eq!(selected.references[0].token, token(35, 1));
        assert_eq!(selected.module_references[0].token, token(26, 1));
        assert!(selected.exported_types.is_empty());
        assert_eq!(selected.fields.len(), 1);
        assert_eq!(selected.fields[0].token, token(4, 1));
        assert_eq!(
            selected.fields[0].declaring_type.as_deref(),
            Some("Example.Outer")
        );
        assert_eq!(selected.fields[0].custom_attributes.len(), 1);
        assert_eq!(
            selected.fields[0].custom_attributes[0].parent_token,
            Some(token(4, 1))
        );
        assert_eq!(selected.generic_params.len(), 1);
        assert_eq!(selected.generic_params[0].source_offset, Some(128));
        assert_eq!(selected.generic_params[0].variance, Some("covariant"));
        assert_eq!(
            selected.generic_params[0].special_constraints,
            vec!["reference-type"]
        );
        assert_eq!(selected.generic_constraints.len(), 1);
        assert_eq!(selected.generic_constraints[0].source_offset, Some(144));
        assert_eq!(
            selected.generic_constraints[0].constraint_token,
            token(2, 1)
        );
        assert_eq!(selected.generic_constraints[0].constraint_kind, "type-def");
        assert_eq!(selected.selection.unmatched_type_names, vec!["Missing"]);
    }

    #[test]
    fn preserves_invalid_generic_constraint_coded_tags_as_issues() {
        let mut rows = vec![0; 64];
        rows[42] = 1;
        rows[44] = 1;
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: Some(TableStream {
                offset: 0,
                valid: (1u64 << 42) | (1u64 << 44),
                rows,
                heap_sizes: 0,
            }),
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: Vec::new(),
            user_strings: Vec::new(),
        };
        let mut bytes = vec![0; 44];
        bytes[40..42].copy_from_slice(&1u16.to_le_bytes());
        bytes[42..44].copy_from_slice(&3u16.to_le_bytes());

        let constraints = root.generic_constraints(&bytes);

        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].owner_token, token(42, 1));
        assert_eq!(constraints[0].constraint_token, "0x00000003");
        assert_eq!(
            constraints[0].issue.as_deref(),
            Some("GenericParamConstraint type coded tag is invalid")
        );
    }

    #[test]
    fn decodes_local_variable_signature_types() {
        let root = MetadataRoot {
            version: String::new(),
            stream_names: Vec::new(),
            row_counts: std::collections::BTreeMap::new(),
            tables: None,
            strings: Vec::new(),
            guids: Vec::new(),
            blobs: vec![0, 4, 0x07, 2, 0x04, 0x0e],
            user_strings: Vec::new(),
        };
        let signature = root.signature(1, "local");
        assert_eq!(signature.parse_status, "decoded");
        assert_eq!(signature.local_types, vec!["int8", "string"]);
    }

    #[test]
    fn decodes_user_string_heap_variants() {
        let heap = vec![0, 5, b'H', 0, b'i', 0, 0, 1, 0, 3, 0, 0xd8, 0];
        assert_eq!(decode_user_string(&heap, 1).unwrap(), "Hi");
        assert_eq!(decode_user_string(&heap, 7).unwrap(), "");
        assert_eq!(
            decode_user_string(&heap, 9),
            Err("user-string contains invalid UTF-16")
        );
        assert_eq!(
            decode_user_string(&heap, 100),
            Err("user-string heap offset is out of bounds")
        );
    }

    #[test]
    fn decodes_custom_attribute_fixed_strings_with_bounded_lengths() {
        assert_eq!(
            decode_attribute_string(&[1, 0, 5, b'H', b'e', b'l', b'l', b'o']),
            Some("Hello".to_owned())
        );
        assert_eq!(decode_attribute_string(&[1, 0, 0]), Some(String::new()));
        assert_eq!(decode_attribute_string(&[1, 0, 0xff]), None);
        assert_eq!(decode_attribute_string(&[1, 0, 4, b'x']), None);
    }

    #[test]
    fn decodes_custom_attribute_serialized_shape_and_preserves_unknowns() {
        let valid = [1, 0, 5, b'H', b'e', b'l', b'l', b'o', 2, 0];
        assert_eq!(decode_attribute_shape(&valid), (Some(1), Some(2), None));

        assert_eq!(
            decode_attribute_shape(&[2, 0, 0]),
            (
                Some(2),
                None,
                Some("CustomAttribute serialized prolog is unsupported".to_owned())
            )
        );
        assert_eq!(
            decode_attribute_shape(&[1, 0, 4, b'x']),
            (
                Some(1),
                None,
                Some("CustomAttribute fixed argument is unsupported or truncated".to_owned())
            )
        );
    }
}
