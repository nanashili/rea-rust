//! `import_managed_reconstruction`.
//!
//! Compatibility owners:
//! `src/server/registerManagedWorkflowTools/importManagedReconstruction.ts`,
//! `src/application/managed/ManagedReconstructionService.ts` and
//! `src/domain/managed/managedReconstruction.ts`.
use super::error::{DomainError, classify};
use super::inspection::{self, InspectionKind};
use crate::common::json;
use rea_core::evidence::envelope::Observation;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value, json};

const OPERATION: &str = "import_managed_reconstruction";

pub fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    // `resolveManagedEvidence(input.static_members)` at the registration
    // boundary: authenticate and require `inspect_managed_members`.
    let static_members = match input.get("static_members") {
        Some(value) => value,
        None => {
            return ToolOutput::Failure(classify(
                OPERATION,
                DomainError::type_error("Managed reconstruction Evidence resolution failed"),
            ));
        }
    };
    let resolved = match super::resolve_expected(static_members, Some("inspect_managed_members")) {
        Ok(record) => record,
        Err(error) => return ToolOutput::Failure(error),
    };

    // `parsed = { ...input, static_members: <resolved> }`.
    let result = match import_reconstruction(&input, &resolved) {
        Ok(evidence_observation) => evidence_observation,
        Err(error) => return ToolOutput::Failure(classify(OPERATION, error)),
    };

    // Record the source Evidence, then the derived result (no unknown).
    if let Err(error) = super::record_authenticated(context.session, &resolved) {
        return ToolOutput::Failure(error);
    }
    match crate::common::create_evidence(
        OPERATION,
        result.subject.as_ref(),
        &crate::common::managed_workflow_provider(),
        result.observation,
    ) {
        Ok(evidence) => super::deliver(context.session, evidence, None),
        Err(error) => ToolOutput::Failure(error),
    }
}

struct DerivedEvidence {
    subject: Option<rea_core::evidence::envelope::SubjectTarget>,
    observation: Observation,
}

/// `importManagedReconstructionEvidenceValidated` + `importManagedReconstruction`
/// + `createManagedReconstructionEvidence`.
fn import_reconstruction(
    input: &Value,
    resolved_members: &Value,
) -> Result<DerivedEvidence, DomainError> {
    let parsed = inspection::parse(
        resolved_members,
        "inspect_managed_members",
        InspectionKind::Members,
    )?;
    let members = &parsed.result;

    let input_methods = input
        .get("methods")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    let mut imported_methods: Vec<Value> = Vec::with_capacity(input_methods.len());
    for candidate in input_methods {
        let observed = find_observed_method(members, candidate).ok_or_else(|| {
            DomainError::type_error(format!(
                "Reconstruction method lock {} does not match a static managed member observation",
                candidate
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            ))
        })?;
        let text = candidate
            .get("reconstruction")
            .and_then(|reconstruction| reconstruction.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let text_sha256 = json::sha256_hex(text.as_bytes());
        verify_text_sha256(candidate, &text_sha256)?;
        imported_methods.push(build_imported_method(observed, candidate, &text_sha256));
    }

    let result = build_result(input, &parsed, members, &imported_methods)?;
    Ok(build_evidence(input, &parsed, members, result))
}

/// `findObservedMethod`.
fn find_observed_method<'a>(members: &'a Value, candidate: &Value) -> Option<&'a Value> {
    let token = candidate.get("token").and_then(Value::as_str);
    let signature_sha256 = candidate.get("signature_sha256").and_then(Value::as_str);
    let candidate_il = candidate
        .get("normalized_il_sha256")
        .and_then(Value::as_str);
    members
        .get("methods")
        .and_then(Value::as_array)?
        .iter()
        .find(|item| {
            let body = item.get("body");
            let item_il = body
                .and_then(|body| body.get("normalized_il_sha256"))
                .and_then(Value::as_str);
            item.get("token").and_then(Value::as_str) == token
                && item
                    .get("signature")
                    .and_then(|signature| signature.get("raw_sha256"))
                    .and_then(Value::as_str)
                    == signature_sha256
                && body
                    .and_then(|body| body.get("status"))
                    .and_then(Value::as_str)
                    == Some("present")
                && item_il.is_some()
                && candidate_il.is_some()
                && item_il == candidate_il
        })
}

/// `verifyTextSha256`.
fn verify_text_sha256(candidate: &Value, text_sha256: &str) -> Result<(), DomainError> {
    if let Some(declared) = candidate
        .get("reconstruction")
        .and_then(|reconstruction| reconstruction.get("text_sha256"))
        .and_then(Value::as_str)
        && declared != text_sha256
    {
        return Err(DomainError::type_error(format!(
            "Reconstruction text hash mismatch for {}",
            candidate
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default()
        )));
    }
    Ok(())
}

/// `countLines`: JS `text.length === 0 ? 0 : text.split(/\r\n|\r|\n/u).length`.
fn count_lines(text: &str) -> u64 {
    if text.is_empty() {
        return 0;
    }
    // Split count = (number of line separators) + 1, where `\r\n` counts once.
    let mut lines: u64 = 1;
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                lines += 1;
                if index + 1 < bytes.len() && bytes[index + 1] == b'\n' {
                    index += 1;
                }
            }
            b'\n' => lines += 1,
            _ => {}
        }
        index += 1;
    }
    lines
}

/// `buildImportedMethod`.
fn build_imported_method(observed: &Value, candidate: &Value, text_sha256: &str) -> Value {
    let reconstruction = candidate
        .get("reconstruction")
        .cloned()
        .unwrap_or(Value::Null);
    let text = reconstruction
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body = observed.get("body");
    json!({
        "token": observed.get("token").cloned().unwrap_or(Value::Null),
        "declaring_type": observed.get("declaring_type").cloned().unwrap_or(Value::Null),
        "name": observed.get("name").cloned().unwrap_or(Value::Null),
        "signature_sha256": observed
            .get("signature")
            .and_then(|signature| signature.get("raw_sha256"))
            .cloned()
            .unwrap_or(Value::Null),
        "normalized_il_sha256": body
            .and_then(|body| body.get("normalized_il_sha256"))
            .cloned()
            .unwrap_or(Value::Null),
        "body_sha256": body
            .and_then(|body| body.get("il_sha256"))
            .cloned()
            .unwrap_or(Value::Null),
        "il_size": body.and_then(|body| body.get("il_size")).cloned().unwrap_or(Value::Null),
        "reconstruction": {
            "kind": reconstruction.get("kind").cloned().unwrap_or(Value::Null),
            "language": reconstruction.get("language").cloned().unwrap_or(Value::Null),
            "text": text,
            "text_sha256": text_sha256,
            "text_length": json::js_len(text),
            "line_count": count_lines(text),
            "source_path": reconstruction.get("source_path").cloned().unwrap_or(Value::Null),
            "start_line": reconstruction.get("start_line").cloned().unwrap_or(Value::Null),
            "end_line": reconstruction.get("end_line").cloned().unwrap_or(Value::Null),
        },
        "validation": {
            "matched_static_member": true,
            "exact_build_required": true,
            "canonical_observation": false,
            "confidence_floor": "inference",
        },
    })
}

const RECONSTRUCTION_LIMITATIONS: [&str; 4] = [
    "Decompiler output is imported as reconstruction evidence and analyst inference; metadata and IL observations remain canonical.",
    "This operation did not execute, load, reflect over, debug, instrument, patch, or decompile the target artifact.",
    "The imported reconstruction is valid only for the exact artifact SHA-256, MVID, method signature, and normalized IL shape recorded here.",
    "Obfuscated names, decompiler variables, and control-flow restructuring are not treated as proof without separate validation.",
];

struct Built {
    result: Value,
    static_observation: Value,
    decompiler: Value,
    method_locks: Value,
    notes: Value,
}

/// `buildReconstructionWithoutId` + `reconstruction_id` + validation.
fn build_result(
    input: &Value,
    parsed: &inspection::ParsedInspection,
    members: &Value,
    methods: &[Value],
) -> Result<Built, DomainError> {
    let static_observation = build_static_observation(parsed, members);
    let decompiler = build_decompiler_record(input)?;
    let summary = build_summary(methods);
    let notes = input.get("notes").cloned().unwrap_or_else(|| json!([]));

    // `Omit<..., "reconstruction_id">` in the exact key order the TS object uses.
    let mut without_id = Map::new();
    without_id.insert("phase".into(), json!("reconstruction-import"));
    without_id.insert("executed".into(), json!(false));
    without_id.insert("static_observation".into(), static_observation.clone());
    without_id.insert("decompiler".into(), decompiler.clone());
    without_id.insert("summary".into(), summary);
    without_id.insert("methods".into(), Value::Array(methods.to_vec()));
    without_id.insert("notes".into(), notes.clone());
    without_id.insert("evidence_links".into(), json!([parsed.evidence_id.clone()]));
    without_id.insert(
        "limitations".into(),
        json!(RECONSTRUCTION_LIMITATIONS.to_vec()),
    );
    let without_id = Value::Object(without_id);

    let reconstruction_id = format!("mre_{}", canonical_digest(&without_id)?);
    // `{ ...withoutId, reconstruction_id }` — spread first, then append the id.
    let mut result = without_id.as_object().cloned().unwrap_or_default();
    result.insert("reconstruction_id".into(), json!(reconstruction_id));

    // Keep the method-lock parameter projection for the Evidence parameters.
    let method_locks = build_method_locks(input);

    Ok(Built {
        result: Value::Object(result),
        static_observation,
        decompiler,
        method_locks,
        notes,
    })
}

/// `buildStaticObservation`.
fn build_static_observation(parsed: &inspection::ParsedInspection, members: &Value) -> Value {
    let module = members.get("module");
    json!({
        "evidence_id": parsed.evidence_id.clone(),
        "artifact_sha256": artifact_field(members, "sha256"),
        "artifact_path": artifact_field(members, "path"),
        "byte_length": artifact_field(members, "byte_length"),
        "module_name": module.and_then(|module| module.get("name")).cloned().unwrap_or(Value::Null),
        "mvid": module.and_then(|module| module.get("mvid")).cloned().unwrap_or(Value::Null),
        "metadata_status": members
            .get("metadata")
            .and_then(|metadata| metadata.get("status"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

fn artifact_field(members: &Value, key: &str) -> Value {
    members
        .get("artifact")
        .and_then(|artifact| artifact.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

/// `buildDecompilerRecord`: `{ ...decompiler, options_sha256 }`.
fn build_decompiler_record(input: &Value) -> Result<Value, DomainError> {
    let decompiler = input.get("decompiler").cloned().unwrap_or(Value::Null);
    let options = decompiler
        .get("options")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let options_sha256 = canonical_digest(&options)?;
    let mut record = decompiler.as_object().cloned().unwrap_or_default();
    record.insert("options_sha256".into(), json!(options_sha256));
    Ok(Value::Object(record))
}

/// `buildReconstructionSummary`.
fn build_summary(methods: &[Value]) -> Value {
    let kind_is = |method: &Value, kind: &str| {
        method
            .get("reconstruction")
            .and_then(|reconstruction| reconstruction.get("kind"))
            .and_then(Value::as_str)
            == Some(kind)
    };
    let total_text_bytes: u64 = methods
        .iter()
        .map(|method| {
            method
                .get("reconstruction")
                .and_then(|reconstruction| reconstruction.get("text"))
                .and_then(Value::as_str)
                .map(|text| text.len() as u64)
                .unwrap_or(0)
        })
        .sum();
    json!({
        "imported_methods": methods.len(),
        "decompiled_csharp_methods": methods.iter().filter(|method| kind_is(method, "decompiled-csharp")).count(),
        "decompiled_il_methods": methods.iter().filter(|method| kind_is(method, "decompiled-il")).count(),
        "pseudocode_methods": methods.iter().filter(|method| kind_is(method, "semantic-pseudocode")).count(),
        "total_text_bytes": total_text_bytes,
    })
}

/// `method_locks`: `{ token, signature_sha256, normalized_il_sha256 }` per input.
fn build_method_locks(input: &Value) -> Value {
    let locks: Vec<Value> = input
        .get("methods")
        .and_then(Value::as_array)
        .map(|methods| {
            methods
                .iter()
                .map(|method| {
                    json!({
                        "token": method.get("token").cloned().unwrap_or(Value::Null),
                        "signature_sha256": method.get("signature_sha256").cloned().unwrap_or(Value::Null),
                        "normalized_il_sha256": method.get("normalized_il_sha256").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Value::Array(locks)
}

/// `createManagedReconstructionEvidence`.
fn build_evidence(
    _input: &Value,
    _parsed: &inspection::ParsedInspection,
    _members: &Value,
    built: Built,
) -> DerivedEvidence {
    let artifact_path = built
        .static_observation
        .get("artifact_path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let artifact_sha256 = built
        .static_observation
        .get("artifact_sha256")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let subject = rea_core::evidence::envelope::SubjectTarget {
        path: artifact_path.clone(),
        sha256: artifact_sha256,
        format: "pe".to_owned(),
        architecture: None,
    };
    let static_evidence_id = built
        .static_observation
        .get("evidence_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let limitations = json::strings(built.result.get("limitations").unwrap_or(&Value::Null));
    let evidence_links = json::strings(built.result.get("evidence_links").unwrap_or(&Value::Null));

    let parameters = json!({
        "static_members_evidence_id": static_evidence_id,
        "decompiler": built.decompiler,
        "method_locks": built.method_locks,
        "notes": built.notes,
    });
    let locations = vec![json!({ "kind": "artifact-path", "path": artifact_path })];

    let observation = Observation::new(OPERATION, parameters, built.result)
        .predicate("rea.managed-reconstruction-import")
        .confidence("inferred")
        .authority("analyst-inference")
        .environment(Value::Null)
        .limitations(limitations)
        .locations(locations)
        .links(evidence_links);
    DerivedEvidence {
        subject: Some(subject),
        observation,
    }
}

/// `sha256(canonicalize(value))`: RFC 8785 canonical digest.
fn canonical_digest(value: &Value) -> Result<String, DomainError> {
    rea_core::canonical_json::digest(value)
        .map_err(|_| DomainError::type_error("Managed reconstruction canonicalization failed"))
}
