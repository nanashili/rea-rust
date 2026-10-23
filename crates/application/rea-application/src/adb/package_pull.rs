//! Validation of a captured `pull_adb_package` result.
//!
//! The ADB provider owns device access, file creation, and digesting.  This
//! module only admits the result that the provider already captured.  In
//! particular, it never checks the host filesystem and never interprets a
//! device path as a host path.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const OPERATION: &str = "pull_adb_package";

const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// The client identity retained by the provider for this operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub binary_path: String,
    pub path_source: PathSource,
    pub version: Option<String>,
    pub installed_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSource {
    Environment,
    Path,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub device_path: String,
    pub file_name: String,
    pub local_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub role: Role,
    pub role_basis: RoleBasis,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Base,
    Split,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleBasis {
    FileName,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PullFailure {
    pub device_path: Option<String>,
    pub stage: FailureStage,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    ResolvePaths,
    Pull,
    Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultProjection {
    pub client: Client,
    pub serial: String,
    pub package_name: String,
    pub output_directory: String,
    pub artifacts: Vec<Artifact>,
    pub failures: Vec<PullFailure>,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    Complete,
    Partial,
}

/// Validate and serialize a captured provider result.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let result: ResultProjection = serde_json::from_value(result_value(input)?.clone())
        .map_err(|_| invalid("captured ADB package pull result is invalid"))?;
    validate_result(&result)?;
    serde_json::to_value(result).map_err(|_| invalid("ADB package pull result is not serializable"))
}

/// Alias used by adapters that expose all native projections as `inspect_value`.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    inspect(input)
}

/// Retain a provider result only when it exactly matches the captured result.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let captured = inspect(input)?;
    let retained = inspect(&result)?;
    if captured != retained {
        return Err(invalid(
            "ADB package pull result does not match the captured result",
        ));
    }
    Ok(result)
}

fn validate_result(result: &ResultProjection) -> Result<(), Failure> {
    validate_client(&result.client)?;
    validate_serial(&result.serial)?;
    validate_package_name(&result.package_name)?;
    validate_absolute_path(&result.output_directory, "output_directory")?;

    let mut destinations = BTreeSet::new();
    for artifact in &result.artifacts {
        validate_artifact(artifact, result, &mut destinations)?;
    }
    for failure in &result.failures {
        validate_failure(failure)?;
    }

    let expected_coverage = if result.failures.is_empty() {
        Coverage::Complete
    } else {
        Coverage::Partial
    };
    if std::mem::discriminant(&result.coverage) != std::mem::discriminant(&expected_coverage) {
        return Err(invalid(
            "coverage must be complete exactly when failures is empty",
        ));
    }

    Ok(())
}

fn validate_client(client: &Client) -> Result<(), Failure> {
    if client.binary_path.is_empty() {
        return Err(invalid("client.binary_path must be non-empty"));
    }
    if client.binary_path.len() > MAX_PATH_BYTES {
        return Err(invalid("client.binary_path is too long"));
    }
    for optional_path in [&client.installed_path] {
        if let Some(path) = optional_path {
            if path.is_empty() || path.len() > MAX_PATH_BYTES {
                return Err(invalid("client.installed_path is invalid"));
            }
        }
    }

    if let Some(version) = &client.version {
        if version.is_empty() {
            return Err(invalid("client.version must be non-empty when present"));
        }
    }

    Ok(())
}

fn validate_artifact(
    artifact: &Artifact,
    result: &ResultProjection,
    destinations: &mut BTreeSet<String>,
) -> Result<(), Failure> {
    validate_absolute_path(&artifact.device_path, "artifact.device_path")?;
    validate_absolute_path(&artifact.local_path, "artifact.local_path")?;

    if artifact.file_name.is_empty()
        || artifact.file_name.len() > MAX_PATH_BYTES
        || artifact.file_name == "."
        || artifact.file_name == ".."
        || artifact.file_name.contains('/')
        || artifact.file_name.contains('\\')
    {
        return Err(invalid(
            "artifact.file_name must be one local path component",
        ));
    }

    if Path::new(artifact.device_path.as_str())
        .file_name()
        .and_then(|name| name.to_str())
        != Some(artifact.file_name.as_str())
    {
        return Err(invalid(
            "artifact.file_name must match the device path basename",
        ));
    }
    if Path::new(artifact.local_path.as_str())
        .file_name()
        .and_then(|name| name.to_str())
        != Some(artifact.file_name.as_str())
    {
        return Err(invalid(
            "artifact.file_name must match the local path basename",
        ));
    }

    let package_directory = Path::new(&result.output_directory).join(&result.package_name);
    if Path::new(&artifact.local_path).parent() != Some(package_directory.as_path()) {
        return Err(invalid(
            "artifact.local_path must remain inside the package output directory",
        ));
    }
    if !destinations.insert(artifact.local_path.clone()) {
        return Err(invalid("artifact.local_path must be unique"));
    }

    if artifact.bytes > MAX_SAFE_INTEGER {
        return Err(invalid(
            "artifact.bytes exceeds the JSON safe integer range",
        ));
    }
    if artifact.sha256.len() != 64
        || artifact
            .sha256
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "artifact.sha256 must be a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_failure(failure: &PullFailure) -> Result<(), Failure> {
    if let Some(device_path) = &failure.device_path {
        validate_absolute_path(device_path, "failure.device_path")?;
    }
    if failure.message.trim().is_empty() || failure.message.len() > MAX_MESSAGE_BYTES {
        return Err(invalid("failure.message must be non-empty and bounded"));
    }
    Ok(())
}

fn result_value(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB package pull result must be an object"))?;
    let result = object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .or_else(|| object.get("value"))
        .unwrap_or(input);
    if !result.is_object() {
        return Err(invalid("ADB package pull result must be an object"));
    }
    Ok(result)
}

fn validate_serial(serial: &str) -> Result<(), Failure> {
    if serial.is_empty()
        || serial.len() > 256
        || serial
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '\0' | '"' | '\''))
    {
        return Err(invalid("serial contains whitespace, quotes, or NUL"));
    }
    Ok(())
}

fn validate_package_name(package_name: &str) -> Result<(), Failure> {
    if package_name.is_empty() || package_name.len() > 256 {
        return Err(invalid("package_name must be non-empty and bounded"));
    }
    for segment in package_name.split('.') {
        if segment.is_empty()
            || !segment
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_alphabetic())
            || segment
                .chars()
                .any(|character| !character.is_ascii_alphanumeric() && character != '_')
        {
            return Err(invalid(
                "package_name must contain dot-separated Java identifiers",
            ));
        }
    }
    Ok(())
}

fn validate_absolute_path(path: &str, field: &str) -> Result<(), Failure> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !Path::new(path).is_absolute()
        || path.contains('\0')
    {
        return Err(invalid(&format!(
            "{field} must be a bounded absolute path without NUL"
        )));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "analysis_input",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a schema-valid captured ADB package pull result and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
