//! Read-only projection of a caller-captured JEB project opening operation.
//!
//! The runtime owns the MCP connection and any IDE or engine I/O. This module
//! validates the request and decoded open-project response, then retains the
//! caller's path, JEB session identity, project identity, and uncertainty.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "open_jeb_project";
const MAX_PATH_LENGTH: usize = 32 * 1024;
const MAX_TEXT_LENGTH: usize = 64 * 1024;
const MAX_INPUT_FILES: usize = 100_000;
const MAX_UNITS: usize = 100_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSelection {
    pub path: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineSession {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub gui_client: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenProjectInformation {
    pub success: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub creation_datetime: Option<String>,
    #[serde(default)]
    pub input_files: Option<Vec<InputFile>>,
    #[serde(default)]
    pub units: Option<Vec<Unit>>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub error: Option<ProviderError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderError {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub recovery_tool: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputFile {
    pub file_name: String,
    pub file_size: u64,
    pub contents_sha256_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub unit_path: String,
    pub unit_type: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EngineIdentity {
    pub name: &'static str,
    pub version: Option<String>,
    pub endpoint: String,
    pub gui_client: Option<bool>,
}

/// Normalized open-project observation with request identity retained.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProjectInspection {
    pub project_path: String,
    pub engine: EngineIdentity,
    pub project_name: Option<String>,
    pub creation_datetime: Option<String>,
    pub input_files: Vec<InputFile>,
    pub units: Vec<Unit>,
    pub limitations: Vec<String>,
}

/// Project a successful, caller-captured JEB open_project response.
pub fn inspect(
    selection: ProjectSelection,
    session: EngineSession,
    information: OpenProjectInformation,
) -> Result<ProjectInspection, Failure> {
    validate_selection(&selection)?;
    validate_session(&session)?;
    validate_information(&information)?;

    if !information.success {
        return Err(refusal_failure(&information));
    }

    let mut limitations = vec![
        "JEB resolved and analyzed the path on the engine host; REA did not open the target itself."
            .to_owned(),
    ];
    if session.version.is_none() {
        limitations.push("The JEB engine did not report its version.".to_owned());
    }
    let input_files = information
        .input_files
        .ok_or_else(|| invalid("successful JEB response omitted input_files"))?;
    let units = information
        .units
        .ok_or_else(|| invalid("successful JEB response omitted units"))?;

    Ok(ProjectInspection {
        project_path: selection.path,
        engine: EngineIdentity {
            name: "jeb",
            version: session.version,
            endpoint: selection.endpoint,
            gui_client: session.gui_client,
        },
        project_name: information.name,
        creation_datetime: information.creation_datetime,
        input_files,
        units,
        limitations,
    })
}

/// Parse the adapter-shaped JSON input while keeping request and session facts
/// separate from the decoded provider response.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("JEB project input must be an object"))?;
    let selection: ProjectSelection = decode_required(object, "selection", "project selection")?;
    let session: EngineSession = decode_required(object, "session", "JEB engine session")?;
    let information: OpenProjectInformation =
        decode_required(object, "response", "captured JEB open-project response")?;

    serde_json::to_value(inspect(selection, session, information)?)
        .map_err(|_| invalid("JEB project inspection result is not serializable"))
}

/// Validate a provider result before wrapping it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let inspected = inspect_value(input)?;
    if result != inspected {
        return Err(invalid(
            "JEB project result does not match the captured open-project response",
        ));
    }
    Ok(result)
}

fn decode_required<T: for<'de> Deserialize<'de>>(
    object: &serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<T, Failure> {
    let value = object
        .get(key)
        .cloned()
        .ok_or_else(|| invalid(&format!("{label} is required")))?;
    serde_json::from_value(value).map_err(|_| invalid(&format!("invalid {label}")))
}

fn validate_selection(selection: &ProjectSelection) -> Result<(), Failure> {
    validate_text(&selection.path, MAX_PATH_LENGTH, "project path")?;
    validate_text(&selection.endpoint, MAX_PATH_LENGTH, "JEB endpoint")
}

fn validate_session(session: &EngineSession) -> Result<(), Failure> {
    if session
        .version
        .as_ref()
        .is_some_and(|value| value.len() > MAX_TEXT_LENGTH)
    {
        return Err(resource_failure(
            "JEB engine version exceeds the 64 KiB bound",
        ));
    }
    Ok(())
}

fn validate_information(information: &OpenProjectInformation) -> Result<(), Failure> {
    let Some(input_files) = information.input_files.as_ref() else {
        if information.success {
            return Err(invalid("successful JEB response omitted input_files"));
        }
        return Ok(());
    };
    let Some(units) = information.units.as_ref() else {
        if information.success {
            return Err(invalid("successful JEB response omitted units"));
        }
        return Ok(());
    };
    if input_files.len() > MAX_INPUT_FILES {
        return Err(resource_failure(
            "JEB input-file results exceed the safety bound",
        ));
    }
    if units.len() > MAX_UNITS {
        return Err(resource_failure("JEB unit results exceed the safety bound"));
    }
    if information
        .message
        .as_ref()
        .is_some_and(|message| message.len() > MAX_TEXT_LENGTH)
    {
        return Err(resource_failure(
            "JEB provider message exceeds the 64 KiB bound",
        ));
    }
    for input_file in input_files {
        validate_text(
            &input_file.file_name,
            MAX_PATH_LENGTH,
            "JEB input-file name",
        )?;
        validate_text(
            &input_file.contents_sha256_hash,
            128,
            "JEB input-file digest",
        )?;
        if input_file.file_size > MAX_SAFE_INTEGER {
            return Err(invalid(
                "JEB input-file size exceeds the JSON safe integer bound",
            ));
        }
    }
    for unit in units {
        validate_text(&unit.unit_path, MAX_PATH_LENGTH, "JEB unit path")?;
        validate_text(&unit.unit_type, MAX_TEXT_LENGTH, "JEB unit type")?;
    }
    Ok(())
}

fn validate_text(value: &str, limit: usize, field: &str) -> Result<(), Failure> {
    if value.trim().is_empty() {
        return Err(invalid(&format!("{field} must not be empty")));
    }
    if value.len() > limit {
        return Err(resource_failure(&format!("{field} exceeds its size bound")));
    }
    Ok(())
}

fn refusal_failure(information: &OpenProjectInformation) -> Failure {
    let reason = information
        .error
        .as_ref()
        .and_then(|error| error.message.as_deref())
        .or(information.message.as_deref())
        .or_else(|| {
            information
                .error
                .as_ref()
                .and_then(|error| error.code.as_deref())
        })
        .unwrap_or("JEB refused the project-opening request");
    Failure::new(
        "provider_refusal",
        "unsupported_target",
        reason.into(),
        false,
        "Use a JEB client that advertises open_project and retry the operation.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("provider", Detail::Text("jeb".into())),
        ]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a caller-selected project path, JEB session, and decoded open-project response."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource_failure(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.into(),
        false,
        "Provide bounded JEB project metadata and retry the operation.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
