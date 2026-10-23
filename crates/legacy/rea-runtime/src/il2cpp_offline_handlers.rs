//! Offline dispatch for retained IL2CPP observations.
//!
//! This adapter owns operation selection at the runtime boundary. Each
//! provider-neutral handler remains responsible for validating and projecting
//! its own input, so this module does not decode bytes, open paths, contact a
//! provider, or reinterpret Evidence.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::{
    il2cpp_artifact_pairing_handler, il2cpp_assembly_join_handler,
    il2cpp_codegen_module_capture_handler, il2cpp_codegen_module_discovery_handler,
    il2cpp_codegen_module_layout_handler, il2cpp_custom_attributes_handler,
    il2cpp_decompilation_join_handler, il2cpp_decompilation_workflow_handler,
    il2cpp_defaults_map_handler, il2cpp_field_layout_map_handler,
    il2cpp_field_layout_workflow_handler, il2cpp_field_offsets_handler,
    il2cpp_generic_constraints_handler, il2cpp_generic_context_handler,
    il2cpp_generic_method_map_handler, il2cpp_image_mapping_handler, il2cpp_internal_calls_handler,
    il2cpp_invoker_map_handler, il2cpp_legacy_metadata_handler, il2cpp_member_metadata_handler,
    il2cpp_method_address_map_handler, il2cpp_method_attributes_handler,
    il2cpp_method_semantics_handler, il2cpp_method_signatures_handler,
    il2cpp_methodspec_map_handler, il2cpp_native_function_join_handler,
    il2cpp_native_xrefs_handler, il2cpp_parameters_handler, il2cpp_pointer_tables_handler,
    il2cpp_registration_scan_handler, il2cpp_registration_tables_handler, il2cpp_rgctx_map_handler,
    il2cpp_static_report_handler, il2cpp_string_literals_handler, il2cpp_symbol_labels_handler,
    il2cpp_type_descriptors_handler, il2cpp_type_hierarchy_handler, il2cpp_typespec_map_handler,
    il2cpp_vtable_map_handler, inspect_il2cpp_metadata_handler,
};

/// IL2CPP operations supported by the offline runtime boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Il2cppOfflineOperation {
    PairArtifacts,
    JoinAssemblies,
    InspectCodegenModuleCapture,
    DiscoverCodegenModules,
    InspectCodegenModuleLayout,
    ProjectCustomAttributes,
    JoinDecompilation,
    CorrelateDecompilation,
    MapDefaultValues,
    MapFieldLayouts,
    ProjectFieldLayouts,
    DecodeFieldOffsets,
    ProjectGenericConstraints,
    ProjectGenericContext,
    MapGenericMethods,
    InspectImage,
    MapInternalCalls,
    MapInvokers,
    InspectMemberMetadata,
    InspectLegacyMetadata,
    MapMethodAddresses,
    InspectMethodAttributes,
    InspectMethodSemantics,
    RenderMethodSignatures,
    MapMethodSpecs,
    JoinNativeFunctions,
    MapNativeXrefs,
    ProjectParameters,
    ProjectPointerTables,
    ScanRegistrationCandidates,
    ProjectRegistrationTables,
    MapRGCTXData,
    ProjectStringLiterals,
    BuildStaticReport,
    LabelSymbols,
    ProjectTypeDescriptors,
    ProjectTypeHierarchy,
    ProjectTypespecs,
    MapVtables,
    InspectMetadata,
}

impl Il2cppOfflineOperation {
    /// Parse the stable operation name exposed by the CLI and MCP contracts.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        let operation = match name {
            il2cpp_artifact_pairing_handler::OPERATION => Self::PairArtifacts,
            il2cpp_assembly_join_handler::OPERATION => Self::JoinAssemblies,
            il2cpp_codegen_module_capture_handler::OPERATION => Self::InspectCodegenModuleCapture,
            il2cpp_codegen_module_discovery_handler::OPERATION => Self::DiscoverCodegenModules,
            il2cpp_codegen_module_layout_handler::OPERATION => Self::InspectCodegenModuleLayout,
            il2cpp_custom_attributes_handler::OPERATION => Self::ProjectCustomAttributes,
            il2cpp_decompilation_join_handler::OPERATION => Self::JoinDecompilation,
            il2cpp_decompilation_workflow_handler::OPERATION => Self::CorrelateDecompilation,
            il2cpp_defaults_map_handler::OPERATION => Self::MapDefaultValues,
            il2cpp_field_layout_map_handler::OPERATION => Self::MapFieldLayouts,
            il2cpp_field_layout_workflow_handler::OPERATION => Self::ProjectFieldLayouts,
            il2cpp_field_offsets_handler::OPERATION => Self::DecodeFieldOffsets,
            il2cpp_generic_constraints_handler::OPERATION => Self::ProjectGenericConstraints,
            il2cpp_generic_context_handler::OPERATION => Self::ProjectGenericContext,
            il2cpp_generic_method_map_handler::OPERATION => Self::MapGenericMethods,
            il2cpp_image_mapping_handler::OPERATION => Self::InspectImage,
            il2cpp_internal_calls_handler::OPERATION => Self::MapInternalCalls,
            il2cpp_invoker_map_handler::OPERATION => Self::MapInvokers,
            il2cpp_legacy_metadata_handler::OPERATION => Self::InspectLegacyMetadata,
            il2cpp_member_metadata_handler::OPERATION => Self::InspectMemberMetadata,
            il2cpp_method_address_map_handler::OPERATION => Self::MapMethodAddresses,
            il2cpp_method_attributes_handler::OPERATION => Self::InspectMethodAttributes,
            il2cpp_method_semantics_handler::OPERATION => Self::InspectMethodSemantics,
            il2cpp_method_signatures_handler::OPERATION => Self::RenderMethodSignatures,
            il2cpp_methodspec_map_handler::OPERATION => Self::MapMethodSpecs,
            il2cpp_native_function_join_handler::OPERATION => Self::JoinNativeFunctions,
            il2cpp_native_xrefs_handler::OPERATION => Self::MapNativeXrefs,
            il2cpp_parameters_handler::OPERATION => Self::ProjectParameters,
            il2cpp_pointer_tables_handler::OPERATION => Self::ProjectPointerTables,
            il2cpp_registration_scan_handler::OPERATION => Self::ScanRegistrationCandidates,
            il2cpp_registration_tables_handler::OPERATION => Self::ProjectRegistrationTables,
            il2cpp_rgctx_map_handler::OPERATION => Self::MapRGCTXData,
            il2cpp_string_literals_handler::OPERATION => Self::ProjectStringLiterals,
            il2cpp_static_report_handler::OPERATION => Self::BuildStaticReport,
            il2cpp_symbol_labels_handler::OPERATION => Self::LabelSymbols,
            il2cpp_type_descriptors_handler::OPERATION => Self::ProjectTypeDescriptors,
            il2cpp_type_hierarchy_handler::OPERATION => Self::ProjectTypeHierarchy,
            il2cpp_typespec_map_handler::OPERATION => Self::ProjectTypespecs,
            il2cpp_vtable_map_handler::OPERATION => Self::MapVtables,
            inspect_il2cpp_metadata_handler::OPERATION => Self::InspectMetadata,
            _ => return Err(unknown_operation(name)),
        };

        Ok(operation)
    }

    /// Return the canonical public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::PairArtifacts => il2cpp_artifact_pairing_handler::OPERATION,
            Self::JoinAssemblies => il2cpp_assembly_join_handler::OPERATION,
            Self::InspectCodegenModuleCapture => il2cpp_codegen_module_capture_handler::OPERATION,
            Self::DiscoverCodegenModules => il2cpp_codegen_module_discovery_handler::OPERATION,
            Self::InspectCodegenModuleLayout => il2cpp_codegen_module_layout_handler::OPERATION,
            Self::ProjectCustomAttributes => il2cpp_custom_attributes_handler::OPERATION,
            Self::JoinDecompilation => il2cpp_decompilation_join_handler::OPERATION,
            Self::CorrelateDecompilation => il2cpp_decompilation_workflow_handler::OPERATION,
            Self::MapDefaultValues => il2cpp_defaults_map_handler::OPERATION,
            Self::MapFieldLayouts => il2cpp_field_layout_map_handler::OPERATION,
            Self::ProjectFieldLayouts => il2cpp_field_layout_workflow_handler::OPERATION,
            Self::DecodeFieldOffsets => il2cpp_field_offsets_handler::OPERATION,
            Self::ProjectGenericConstraints => il2cpp_generic_constraints_handler::OPERATION,
            Self::ProjectGenericContext => il2cpp_generic_context_handler::OPERATION,
            Self::MapGenericMethods => il2cpp_generic_method_map_handler::OPERATION,
            Self::InspectImage => il2cpp_image_mapping_handler::OPERATION,
            Self::MapInternalCalls => il2cpp_internal_calls_handler::OPERATION,
            Self::MapInvokers => il2cpp_invoker_map_handler::OPERATION,
            Self::InspectLegacyMetadata => il2cpp_legacy_metadata_handler::OPERATION,
            Self::InspectMemberMetadata => il2cpp_member_metadata_handler::OPERATION,
            Self::MapMethodAddresses => il2cpp_method_address_map_handler::OPERATION,
            Self::InspectMethodAttributes => il2cpp_method_attributes_handler::OPERATION,
            Self::InspectMethodSemantics => il2cpp_method_semantics_handler::OPERATION,
            Self::RenderMethodSignatures => il2cpp_method_signatures_handler::OPERATION,
            Self::MapMethodSpecs => il2cpp_methodspec_map_handler::OPERATION,
            Self::JoinNativeFunctions => il2cpp_native_function_join_handler::OPERATION,
            Self::MapNativeXrefs => il2cpp_native_xrefs_handler::OPERATION,
            Self::ProjectParameters => il2cpp_parameters_handler::OPERATION,
            Self::ProjectPointerTables => il2cpp_pointer_tables_handler::OPERATION,
            Self::ScanRegistrationCandidates => il2cpp_registration_scan_handler::OPERATION,
            Self::ProjectRegistrationTables => il2cpp_registration_tables_handler::OPERATION,
            Self::MapRGCTXData => il2cpp_rgctx_map_handler::OPERATION,
            Self::ProjectStringLiterals => il2cpp_string_literals_handler::OPERATION,
            Self::BuildStaticReport => il2cpp_static_report_handler::OPERATION,
            Self::LabelSymbols => il2cpp_symbol_labels_handler::OPERATION,
            Self::ProjectTypeDescriptors => il2cpp_type_descriptors_handler::OPERATION,
            Self::ProjectTypeHierarchy => il2cpp_type_hierarchy_handler::OPERATION,
            Self::ProjectTypespecs => il2cpp_typespec_map_handler::OPERATION,
            Self::MapVtables => il2cpp_vtable_map_handler::OPERATION,
            Self::InspectMetadata => inspect_il2cpp_metadata_handler::OPERATION,
        }
    }
}

/// Dispatch one captured IL2CPP operation without acquiring external resources.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    dispatch_typed(Il2cppOfflineOperation::parse(operation)?, &input)
}

/// Dispatch an already-parsed operation and preserve the caller's input value.
pub fn dispatch_typed(operation: Il2cppOfflineOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        Il2cppOfflineOperation::PairArtifacts => {
            il2cpp_artifact_pairing_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::JoinAssemblies => {
            il2cpp_assembly_join_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::InspectCodegenModuleCapture => {
            il2cpp_codegen_module_capture_handler::handle(input)
        }
        Il2cppOfflineOperation::DiscoverCodegenModules => {
            il2cpp_codegen_module_discovery_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::InspectCodegenModuleLayout => {
            il2cpp_codegen_module_layout_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectCustomAttributes => {
            il2cpp_custom_attributes_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::JoinDecompilation => {
            il2cpp_decompilation_join_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::CorrelateDecompilation => {
            il2cpp_decompilation_workflow_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapDefaultValues => {
            il2cpp_defaults_map_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapFieldLayouts => {
            il2cpp_field_layout_map_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectFieldLayouts => {
            il2cpp_field_layout_workflow_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::DecodeFieldOffsets => {
            il2cpp_field_offsets_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectGenericConstraints => {
            il2cpp_generic_constraints_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectGenericContext => {
            il2cpp_generic_context_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapGenericMethods => {
            il2cpp_generic_method_map_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::InspectImage => il2cpp_image_mapping_handler::dispatch_typed(input),
        Il2cppOfflineOperation::MapInternalCalls => {
            il2cpp_internal_calls_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapInvokers => il2cpp_invoker_map_handler::dispatch_typed(input),
        Il2cppOfflineOperation::InspectLegacyMetadata => {
            il2cpp_legacy_metadata_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::InspectMemberMetadata => {
            il2cpp_member_metadata_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapMethodAddresses => {
            il2cpp_method_address_map_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::InspectMethodAttributes => {
            il2cpp_method_attributes_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::InspectMethodSemantics => {
            il2cpp_method_semantics_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::RenderMethodSignatures => {
            il2cpp_method_signatures_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapMethodSpecs => {
            il2cpp_methodspec_map_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::JoinNativeFunctions => {
            il2cpp_native_function_join_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapNativeXrefs => {
            il2cpp_native_xrefs_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectParameters => {
            il2cpp_parameters_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectPointerTables => {
            il2cpp_pointer_tables_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ScanRegistrationCandidates => {
            il2cpp_registration_scan_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectRegistrationTables => {
            il2cpp_registration_tables_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapRGCTXData => il2cpp_rgctx_map_handler::dispatch_typed(input),
        Il2cppOfflineOperation::ProjectStringLiterals => {
            il2cpp_string_literals_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::BuildStaticReport => {
            il2cpp_static_report_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::LabelSymbols => il2cpp_symbol_labels_handler::dispatch_typed(input),
        Il2cppOfflineOperation::ProjectTypeDescriptors => {
            il2cpp_type_descriptors_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectTypeHierarchy => {
            il2cpp_type_hierarchy_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::ProjectTypespecs => {
            il2cpp_typespec_map_handler::dispatch_typed(input)
        }
        Il2cppOfflineOperation::MapVtables => il2cpp_vtable_map_handler::dispatch_typed(input),
        Il2cppOfflineOperation::InspectMetadata => inspect_il2cpp_metadata_handler::handle(input),
    }
}

/// Check whether an operation is handled by this captured-only adapter.
pub fn supports(name: &str) -> bool {
    Il2cppOfflineOperation::parse(name).is_ok()
}

/// Return the operation names recognized by this adapter.
pub const fn operation_names() -> &'static [&'static str] {
    &[
        il2cpp_artifact_pairing_handler::OPERATION,
        il2cpp_assembly_join_handler::OPERATION,
        il2cpp_codegen_module_capture_handler::OPERATION,
        il2cpp_codegen_module_discovery_handler::OPERATION,
        il2cpp_codegen_module_layout_handler::OPERATION,
        il2cpp_custom_attributes_handler::OPERATION,
        il2cpp_decompilation_join_handler::OPERATION,
        il2cpp_decompilation_workflow_handler::OPERATION,
        il2cpp_defaults_map_handler::OPERATION,
        il2cpp_field_layout_map_handler::OPERATION,
        il2cpp_field_layout_workflow_handler::OPERATION,
        il2cpp_field_offsets_handler::OPERATION,
        il2cpp_generic_constraints_handler::OPERATION,
        il2cpp_generic_context_handler::OPERATION,
        il2cpp_generic_method_map_handler::OPERATION,
        il2cpp_image_mapping_handler::OPERATION,
        il2cpp_internal_calls_handler::OPERATION,
        il2cpp_invoker_map_handler::OPERATION,
        il2cpp_legacy_metadata_handler::OPERATION,
        il2cpp_member_metadata_handler::OPERATION,
        il2cpp_method_address_map_handler::OPERATION,
        il2cpp_method_attributes_handler::OPERATION,
        il2cpp_method_semantics_handler::OPERATION,
        il2cpp_method_signatures_handler::OPERATION,
        il2cpp_methodspec_map_handler::OPERATION,
        il2cpp_native_function_join_handler::OPERATION,
        il2cpp_native_xrefs_handler::OPERATION,
        il2cpp_parameters_handler::OPERATION,
        il2cpp_pointer_tables_handler::OPERATION,
        il2cpp_registration_scan_handler::OPERATION,
        il2cpp_registration_tables_handler::OPERATION,
        il2cpp_rgctx_map_handler::OPERATION,
        il2cpp_string_literals_handler::OPERATION,
        il2cpp_static_report_handler::OPERATION,
        il2cpp_symbol_labels_handler::OPERATION,
        il2cpp_type_descriptors_handler::OPERATION,
        il2cpp_type_hierarchy_handler::OPERATION,
        il2cpp_typespec_map_handler::OPERATION,
        il2cpp_vtable_map_handler::OPERATION,
        inspect_il2cpp_metadata_handler::OPERATION,
    ]
}

/// Map the hyphenated CLI command spelling to its contract operation name.
pub fn operation_for_cli(command: &str) -> Option<&'static str> {
    match command {
        "pair-il2cpp-artifacts" => Some(il2cpp_artifact_pairing_handler::OPERATION),
        "join-il2cpp-assemblies" => Some(il2cpp_assembly_join_handler::OPERATION),
        "inspect-il2cpp-codegen-module-capture" => {
            Some(il2cpp_codegen_module_capture_handler::OPERATION)
        }
        "discover-il2cpp-codegen-modules" => {
            Some(il2cpp_codegen_module_discovery_handler::OPERATION)
        }
        "inspect-il2cpp-codegen-module-layout" => {
            Some(il2cpp_codegen_module_layout_handler::OPERATION)
        }
        "project-il2cpp-custom-attributes" => Some(il2cpp_custom_attributes_handler::OPERATION),
        "join-il2cpp-decompilation" => Some(il2cpp_decompilation_join_handler::OPERATION),
        "correlate-il2cpp-decompilation" => Some(il2cpp_decompilation_workflow_handler::OPERATION),
        "map-il2cpp-default-values" => Some(il2cpp_defaults_map_handler::OPERATION),
        "map-il2cpp-field-layouts" => Some(il2cpp_field_layout_map_handler::OPERATION),
        "project-il2cpp-field-layouts" => Some(il2cpp_field_layout_workflow_handler::OPERATION),
        "decode-il2cpp-field-offsets" => Some(il2cpp_field_offsets_handler::OPERATION),
        "project-il2cpp-generic-constraints" => Some(il2cpp_generic_constraints_handler::OPERATION),
        "project-il2cpp-generic-context" => Some(il2cpp_generic_context_handler::OPERATION),
        "map-il2cpp-generic-methods" => Some(il2cpp_generic_method_map_handler::OPERATION),
        "inspect-il2cpp-image" => Some(il2cpp_image_mapping_handler::OPERATION),
        "map-il2cpp-internal-calls" => Some(il2cpp_internal_calls_handler::OPERATION),
        "map-il2cpp-invokers" => Some(il2cpp_invoker_map_handler::OPERATION),
        "inspect-il2cpp-legacy-metadata" => Some(il2cpp_legacy_metadata_handler::OPERATION),
        "inspect-il2cpp-member-metadata" => Some(il2cpp_member_metadata_handler::OPERATION),
        "map-il2cpp-method-addresses" => Some(il2cpp_method_address_map_handler::OPERATION),
        "inspect-il2cpp-method-attributes" => Some(il2cpp_method_attributes_handler::OPERATION),
        "inspect-il2cpp-method-semantics" => Some(il2cpp_method_semantics_handler::OPERATION),
        "render-il2cpp-method-signatures" => Some(il2cpp_method_signatures_handler::OPERATION),
        "map-il2cpp-method-specs" => Some(il2cpp_methodspec_map_handler::OPERATION),
        "join-il2cpp-native-functions" => Some(il2cpp_native_function_join_handler::OPERATION),
        "map-il2cpp-native-xrefs" => Some(il2cpp_native_xrefs_handler::OPERATION),
        "project-il2cpp-parameters" => Some(il2cpp_parameters_handler::OPERATION),
        "project-il2cpp-pointer-tables" => Some(il2cpp_pointer_tables_handler::OPERATION),
        "scan-il2cpp-registration" => Some(il2cpp_registration_scan_handler::OPERATION),
        "project-il2cpp-registration-tables" => Some(il2cpp_registration_tables_handler::OPERATION),
        "inspect-il2cpp-rgctx-map" => Some(il2cpp_rgctx_map_handler::OPERATION),
        "project-il2cpp-string-literals" => Some(il2cpp_string_literals_handler::OPERATION),
        "build-il2cpp-static-report" => Some(il2cpp_static_report_handler::OPERATION),
        "label-il2cpp-symbols" => Some(il2cpp_symbol_labels_handler::OPERATION),
        "project-il2cpp-type-descriptors" => Some(il2cpp_type_descriptors_handler::OPERATION),
        "project-il2cpp-type-hierarchy" => Some(il2cpp_type_hierarchy_handler::OPERATION),
        "project-il2cpp-typespecs" => Some(il2cpp_typespec_map_handler::OPERATION),
        "map-il2cpp-vtables" => Some(il2cpp_vtable_map_handler::OPERATION),
        "inspect-il2cpp-metadata" => Some(inspect_il2cpp_metadata_handler::OPERATION),
        _ => None,
    }
}

/// Return the contract JSON owned by each recognized operation.
pub const fn contract_sources() -> &'static [(&'static str, &'static str)] {
    &[
        (
            il2cpp_artifact_pairing_handler::OPERATION,
            include_str!("../contracts/pair_il2cpp_artifacts.json"),
        ),
        (
            il2cpp_assembly_join_handler::OPERATION,
            include_str!("../contracts/join_il2cpp_assemblies.json"),
        ),
        (
            il2cpp_codegen_module_capture_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_codegen_module_capture.json"),
        ),
        (
            il2cpp_codegen_module_discovery_handler::OPERATION,
            include_str!("../contracts/discover_il2cpp_codegen_modules.json"),
        ),
        (
            il2cpp_codegen_module_layout_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_codegen_module_layout.json"),
        ),
        (
            il2cpp_custom_attributes_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_custom_attributes.json"),
        ),
        (
            il2cpp_decompilation_join_handler::OPERATION,
            include_str!("../contracts/join_il2cpp_decompilation.json"),
        ),
        (
            il2cpp_decompilation_workflow_handler::OPERATION,
            include_str!("../contracts/correlate_il2cpp_decompilation.json"),
        ),
        (
            il2cpp_defaults_map_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_default_values.json"),
        ),
        (
            il2cpp_field_layout_map_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_field_layouts.json"),
        ),
        (
            il2cpp_field_layout_workflow_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_field_layouts.json"),
        ),
        (
            il2cpp_field_offsets_handler::OPERATION,
            include_str!("../contracts/decode_il2cpp_field_offsets.json"),
        ),
        (
            il2cpp_generic_constraints_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_generic_constraints.json"),
        ),
        (
            il2cpp_generic_context_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_generic_context.json"),
        ),
        (
            il2cpp_generic_method_map_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_generic_methods.json"),
        ),
        (
            il2cpp_image_mapping_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_image.json"),
        ),
        (
            il2cpp_internal_calls_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_internal_calls.json"),
        ),
        (
            il2cpp_invoker_map_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_invokers.json"),
        ),
        (
            il2cpp_legacy_metadata_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_legacy_metadata.json"),
        ),
        (
            il2cpp_member_metadata_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_member_metadata.json"),
        ),
        (
            il2cpp_method_address_map_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_method_addresses.json"),
        ),
        (
            il2cpp_method_attributes_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_method_attributes.json"),
        ),
        (
            il2cpp_method_semantics_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_method_semantics.json"),
        ),
        (
            il2cpp_method_signatures_handler::OPERATION,
            include_str!("../contracts/render_il2cpp_method_signatures.json"),
        ),
        (
            il2cpp_methodspec_map_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_method_specs.json"),
        ),
        (
            il2cpp_native_function_join_handler::OPERATION,
            include_str!("../contracts/join_il2cpp_native_functions.json"),
        ),
        (
            il2cpp_native_xrefs_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_native_xrefs.json"),
        ),
        (
            il2cpp_parameters_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_parameters.json"),
        ),
        (
            il2cpp_pointer_tables_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_pointer_tables.json"),
        ),
        (
            il2cpp_registration_scan_handler::OPERATION,
            include_str!("../contracts/scan_il2cpp_registration_candidates.json"),
        ),
        (
            il2cpp_registration_tables_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_registration_tables.json"),
        ),
        (
            il2cpp_rgctx_map_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_rgctx_map.json"),
        ),
        (
            il2cpp_string_literals_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_string_literals.json"),
        ),
        (
            il2cpp_static_report_handler::OPERATION,
            include_str!("../contracts/build_il2cpp_static_report.json"),
        ),
        (
            il2cpp_symbol_labels_handler::OPERATION,
            include_str!("../contracts/label_il2cpp_symbols.json"),
        ),
        (
            il2cpp_type_descriptors_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_type_descriptors.json"),
        ),
        (
            il2cpp_type_hierarchy_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_type_hierarchy.json"),
        ),
        (
            il2cpp_typespec_map_handler::OPERATION,
            include_str!("../contracts/project_il2cpp_typespecs.json"),
        ),
        (
            il2cpp_vtable_map_handler::OPERATION,
            include_str!("../contracts/map_il2cpp_vtables.json"),
        ),
        (
            inspect_il2cpp_metadata_handler::OPERATION,
            include_str!("../contracts/inspect_il2cpp_metadata.json"),
        ),
    ]
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("IL2CPP operation is unknown: {name}"),
        false,
        "Select a supported captured IL2CPP operation.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
