//! Dispatch for retained managed-code workflow observations.
//!
//! Provider adapters own artifact reading and source Evidence creation. This
//! module projects caller-supplied managed Evidence through provider-neutral
//! application workflows and records their derived Evidence; it never loads
//! assemblies, reads metadata files, or contacts a native analysis provider.

use rea_application::{il2cpp, managed};
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Managed operations recognized by the native runtime boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedOperation {
    InspectArtifact,
    CompareMembers,
    VerifyNativeBoundaries,
    ImportReconstruction,
    ProjectApplicationGraph,
    InspectIl2cppMetadata,
}

impl ManagedOperation {
    /// Parse the stable operation name exposed by the CLI and MCP contracts.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            managed::artifact::OPERATION => Ok(Self::InspectArtifact),
            "compare_managed_members" => Ok(Self::CompareMembers),
            "verify_managed_native_boundaries" => Ok(Self::VerifyNativeBoundaries),
            "import_managed_reconstruction" => Ok(Self::ImportReconstruction),
            "project_managed_application_graph" => Ok(Self::ProjectApplicationGraph),
            il2cpp::metadata::OPERATION => Ok(Self::InspectIl2cppMetadata),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectArtifact => managed::artifact::OPERATION,
            Self::CompareMembers => "compare_managed_members",
            Self::VerifyNativeBoundaries => "verify_managed_native_boundaries",
            Self::ImportReconstruction => "import_managed_reconstruction",
            Self::ProjectApplicationGraph => "project_managed_application_graph",
            Self::InspectIl2cppMetadata => il2cpp::metadata::OPERATION,
        }
    }
}

/// Dispatch one managed workflow using only retained caller-supplied input.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = ManagedOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed managed operation without opening an artifact.
pub fn dispatch_typed(operation: ManagedOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        ManagedOperation::CompareMembers => managed::member_comparison::compare(input)
            .map_err(|reason| workflow_failure(operation, reason)),
        ManagedOperation::VerifyNativeBoundaries => {
            let result = managed::native_verification::verify(input)
                .map_err(|reason| workflow_failure(operation, reason))?;
            create_verification_evidence(input, result)
                .map_err(|reason| workflow_failure(operation, reason))
        }
        ManagedOperation::ImportReconstruction => {
            managed::reconstruction::import_reconstruction(input)
                .map_err(|reason| workflow_failure(operation, reason))
        }
        ManagedOperation::ProjectApplicationGraph => managed::application_graph::project(input)
            .map_err(|reason| workflow_failure(operation, reason)),
        ManagedOperation::InspectArtifact | ManagedOperation::InspectIl2cppMetadata => {
            Err(byte_backed_operation(operation))
        }
    }
}

fn create_verification_evidence(input: &Value, result: Value) -> Result<Value, String> {
    let managed_boundary_id = input
        .pointer("/managed_boundaries/evidence_id")
        .and_then(Value::as_str)
        .ok_or("managed_boundaries.evidence_id is required")?;
    let native_ids = input
        .get("native_observations")
        .and_then(Value::as_array)
        .ok_or("native_observations must be an array")?
        .iter()
        .map(|observation| {
            observation
                .get("evidence_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or("native_observations entries require evidence_id")
        })
        .collect::<Result<Vec<_>, _>>()?;

    let limitations = result
        .get("limitations")
        .cloned()
        .ok_or("verification result has no limitations")?;
    let evidence_links = result
        .get("evidence_links")
        .cloned()
        .ok_or("verification result has no evidence_links")?;
    let unsigned = json!({
        "subject": null,
        "provider": {
            "id": "rea-dotnet-workflows",
            "name": "REA managed-code workflows",
            "version": "1"
        },
        "analysis_profile": null,
        "predicate_type": "rea.managed-native-verification",
        "operation": "verify_managed_native_boundaries",
        "parameters": {
            "managed_boundaries_evidence_id": managed_boundary_id,
            "native_evidence_ids": native_ids
        },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "inferred",
        "authority": "analyst-inference",
        "environment": null,
        "limitations": limitations,
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": evidence_links
    });
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| format!("verification Evidence could not be encoded: {error}"))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| format!("verification Evidence is invalid: {error}"))?;
    serde_json::from_str(evidence.raw().get())
        .map_err(|error| format!("verification Evidence could not be decoded: {error}"))
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Managed operation is unknown: {name}"),
        false,
        "Select a supported managed operation.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn byte_backed_operation(operation: ManagedOperation) -> Failure {
    Failure::new(
        "unsupported_request",
        "unsupported_request",
        format!(
            "{} requires the artifact-owning inspection adapter and cannot run from retained workflow input",
            operation.name()
        ),
        false,
        "Route the explicit artifact through its owning inspection workflow first.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    )
}

fn workflow_failure(operation: ManagedOperation, reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason,
        false,
        "Provide the required authenticated managed Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    )
}
