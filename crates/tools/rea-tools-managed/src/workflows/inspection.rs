//! `parseManagedInspectionEvidence` and the historical-default normalization
//! that the managed inspection schemas apply on parse.
//!
//! Compatibility owners: `src/domain/managed/managedInspectionEvidence.ts`
//! and the `*.default(...)` fields of `src/domain/managed/managedArtifact.ts`.
//!
//! The handler already authenticated the record and checked its operation at
//! the registration boundary (`resolveManaged*Evidence`); the domain
//! re-authenticates the canonical value here, then cross-checks the artifact
//! digest and module token scope exactly as the TypeScript does.
use super::error::DomainError;
use serde_json::{Map, Value};

/// A parsed managed inspection Evidence record: its id and normalized result.
pub struct ParsedInspection {
    pub evidence_id: String,
    pub result: Value,
}

/// Which managed inspection schema applies, so defaults match the producer.
#[derive(Clone, Copy)]
pub enum InspectionKind {
    Artifact,
    Members,
    Boundary,
}

/// `managedTokenScopesMatch`: tokens join only under a known, matching MVID.
pub fn token_scopes_match(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    }
}

/// `parseManagedInspectionEvidence(rawEvidence, operation, schema)`.
pub fn parse(
    value: &Value,
    operation: &str,
    kind: InspectionKind,
) -> Result<ParsedInspection, DomainError> {
    let record = super::authenticate(value)?;
    let evidence_operation = record
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("");
    if evidence_operation != operation {
        return Err(DomainError::type_error(format!(
            "Evidence operation is not {operation}"
        )));
    }
    let evidence_id = record
        .get("evidence_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let subject = record.get("subject").cloned().unwrap_or(Value::Null);
    let normalized = record
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    let result = normalize(normalized, kind);

    let artifact_sha256 = result
        .get("artifact")
        .and_then(|artifact| artifact.get("sha256"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    // A null subject remains valid and means there is no digest to cross-check.
    let subject_sha256 = subject
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str);
    if let Some(subject_sha256) = subject_sha256
        && artifact_sha256 != subject_sha256
    {
        return Err(DomainError::type_error(format!(
            "Managed Evidence {operation} ({evidence_id}) subject SHA-256 {subject_sha256} does not match normalized artifact SHA-256 {artifact_sha256}"
        )));
    }

    // `identity_scope` is present for member and boundary inspections.
    if let Some(scope) = result.get("identity_scope") {
        let required_sha256 = scope
            .get("requires_artifact_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if required_sha256 != artifact_sha256 {
            return Err(DomainError::type_error(format!(
                "Managed Evidence {operation} ({evidence_id}) token scope SHA-256 {required_sha256} does not match normalized artifact SHA-256 {artifact_sha256}"
            )));
        }
        let module_mvid = result
            .get("module")
            .and_then(|module| module.get("mvid"))
            .and_then(Value::as_str);
        // `requires_mvid` is a declared (possibly null) key, so its presence
        // is what makes the scope MVID comparison run.
        if let Some(scoped_mvid_value) = scope.get("requires_mvid") {
            let scoped_mvid = scoped_mvid_value.as_str();
            if lower(scoped_mvid) != lower(module_mvid) {
                return Err(DomainError::type_error(format!(
                    "Managed Evidence {operation} ({evidence_id}) token scope MVID {} does not match module MVID {}",
                    stringify_optional(scoped_mvid),
                    stringify_optional(module_mvid),
                )));
            }
        }
    }

    Ok(ParsedInspection {
        evidence_id,
        result,
    })
}

/// `String(x)` of an optional string: `"null"` when absent.
fn stringify_optional(value: Option<&str>) -> String {
    value
        .map(str::to_owned)
        .unwrap_or_else(|| "null".to_owned())
}

fn lower(value: Option<&str>) -> Option<String> {
    value.map(str::to_lowercase)
}

/// Apply the schema's historical `.default(...)` values to the fields the
/// workflows consume, and leave the rest of the validated result untouched.
fn normalize(value: Value, kind: InspectionKind) -> Value {
    let Value::Object(mut object) = value else {
        return value;
    };
    match kind {
        InspectionKind::Artifact => {
            normalize_types(&mut object);
        }
        InspectionKind::Members => {
            default_key(&mut object, "signature_resolution", Value::Null);
            default_key(&mut object, "nesting_read", Value::Null);
            default_key(&mut object, "exported_types", Value::Null);
            default_key(&mut object, "user_strings", Value::Null);
            default_key(&mut object, "selection", Value::Null);
            normalize_types(&mut object);
            normalize_members(&mut object, "methods");
            normalize_members(&mut object, "fields");
        }
        InspectionKind::Boundary => {}
    }
    Value::Object(object)
}

/// `managedTypeSchema`: `name_sha256` and `enclosing_type_token` default null.
fn normalize_types(object: &mut Map<String, Value>) {
    if let Some(Value::Array(types)) = object.get_mut("types") {
        for type_row in types {
            if let Value::Object(row) = type_row {
                default_key(row, "name_sha256", Value::Null);
                default_key(row, "enclosing_type_token", Value::Null);
            }
        }
    }
}

/// `managedSignatureSchema.resolved_sha256` defaults null on each member.
fn normalize_members(object: &mut Map<String, Value>, key: &str) {
    if let Some(Value::Array(members)) = object.get_mut(key) {
        for member in members {
            if let Value::Object(member) = member
                && let Some(Value::Object(signature)) = member.get_mut("signature")
            {
                default_key(signature, "resolved_sha256", Value::Null);
            }
        }
    }
}

/// Insert `default_value` only when the key is absent (Zod `.default`).
fn default_key(object: &mut Map<String, Value>, key: &str, default_value: Value) {
    object.entry(key.to_owned()).or_insert(default_value);
}
