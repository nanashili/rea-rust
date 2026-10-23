//! JEB provider adapter: serve REA's JEB operations from a running engine
//! client over MCP, projecting portable observations with engine provenance.
//!
//! Compatibility owners: `src/jeb/JebProvider.ts`, `src/composition/jeb.ts`
//! (`createJebAnalysisProvider`) and `src/config/environment.ts`
//! (`parseJebMcpTimeoutMs`). The engine resolves and analyzes the target on its
//! own host; REA never launches the engine or reads the target file.
use super::endpoint::{DEFAULT_JEB_MCP_ENDPOINT, Endpoint, parse_jeb_mcp_endpoint};
use super::mcp::{JEB_ENGINE_TOOLS, JebMcpConnection, PhysicalFailure};
use crate::common::evidence::Execution;
use rea_core::analysis_error::{AnalysisError, ErrorKind, SettingIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::EvidenceProvider;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

/// `JEB_PROVIDER_IDENTITY`.
pub const PROVIDER_ID: &str = "jeb";
pub const PROVIDER_NAME: &str = "JEB";

/// Node schedules delays above this signed 32-bit boundary as a 1 ms timer.
const MAX_TIMER_DELAY_MS: u64 = 2_147_483_647;

/// SDK `DEFAULT_REQUEST_TIMEOUT_MSEC` for discovery and per-call deadlines.
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 60_000;

/// Provider construction outcome, mirroring `createJebAnalysisProvider`: an
/// unusable endpoint or timeout makes only JEB unavailable.
pub enum ProviderBuild {
    /// A usable provider bound to the caller-selected endpoint.
    Ready(JebProvider),
    /// The configured endpoint or timeout was invalid; JEB is unavailable and
    /// every operation fails with this configuration error.
    Unconfigured {
        setting: String,
        reason: String,
        error: AnalysisError,
    },
}

/// Construct one JEB provider bound to the caller-selected MCP endpoint.
///
/// Compatibility owner: `createJebAnalysisProvider`.
pub fn build_provider(environment: &HashMap<String, String>) -> ProviderBuild {
    let request_timeout = match parse_jeb_mcp_timeout_ms(crate::common::env::lookup(
        environment,
        "REA_JEB_MCP_TIMEOUT_MS",
    )) {
        Ok(value) => value,
        Err((setting, reason, error)) => {
            return ProviderBuild::Unconfigured {
                setting,
                reason,
                error,
            };
        }
    };

    let endpoint =
        parse_jeb_mcp_endpoint(crate::common::env::lookup(environment, "REA_JEB_MCP_URL"));
    match endpoint {
        Ok(endpoint) => ProviderBuild::Ready(JebProvider::new(endpoint, request_timeout)),
        Err(error) => {
            // `AnalysisInputError` from the endpoint parser becomes a
            // `ConfigurationError` on REA_JEB_MCP_URL (composition catch).
            let constraint = endpoint_constraint(&error);
            let configuration = AnalysisError::configuration(
                "Invalid REA environment configuration",
                vec![SettingIssue {
                    setting: "REA_JEB_MCP_URL".to_owned(),
                    constraint: constraint.clone(),
                }],
            );
            ProviderBuild::Unconfigured {
                setting: "REA_JEB_MCP_URL".to_owned(),
                reason: constraint,
                error: configuration,
            }
        }
    }
}

/// The constraint text an `AnalysisInputError` carries (`cause` string).
fn endpoint_constraint(error: &AnalysisError) -> String {
    if let ErrorKind::Input { issues, .. } = &error.kind
        && let Some(issue) = issues.first()
        && let Some(message) = &issue.message
    {
        return message.clone();
    }
    error.user_message()
}

/// Parse `REA_JEB_MCP_TIMEOUT_MS` without reading the ambient environment.
///
/// Compatibility owner: `parseJebMcpTimeoutMs` over `providerStartupTimeoutSchema`.
fn parse_jeb_mcp_timeout_ms(
    value: Option<&str>,
) -> Result<Option<u64>, (String, String, AnalysisError)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let decimal_positive = !value.is_empty()
        && value.as_bytes()[0] != b'0'
        && value.bytes().all(|byte| byte.is_ascii_digit());
    let parsed = if decimal_positive {
        value.parse::<u64>().ok()
    } else {
        None
    };
    match parsed {
        Some(parsed) if (1..=MAX_TIMER_DELAY_MS).contains(&parsed) => Ok(Some(parsed)),
        _ => {
            let constraint = if decimal_positive {
                format!("must be at most {MAX_TIMER_DELAY_MS}")
            } else {
                "must be a positive decimal integer".to_owned()
            };
            let error = AnalysisError::configuration(
                "Invalid REA environment configuration",
                vec![SettingIssue {
                    setting: "REA_JEB_MCP_TIMEOUT_MS".to_owned(),
                    constraint: constraint.clone(),
                }],
            );
            Err(("REA_JEB_MCP_TIMEOUT_MS".to_owned(), constraint, error))
        }
    }
}

/// Unavailable `ProviderAvailability` for an unusable configuration.
///
/// Compatibility owner: `unconfiguredJebProvider.inspectAvailability`.
pub fn availability_unavailable(setting: &str, reason: &str) -> Value {
    json!({
        "status": "unavailable",
        "code": "not_configured",
        "reason": reason,
        "diagnostics": { "setting": setting },
    })
}

/// Serve REA's JEB operations from a running engine client over MCP.
pub struct JebProvider {
    connection: JebMcpConnection,
    endpoint: Endpoint,
    /// Cached client information (`version`, `gui_client`) once observed.
    client_information: std::sync::Mutex<Option<ClientInformation>>,
}

#[derive(Clone, Default)]
struct ClientInformation {
    version: Option<String>,
    gui_client: Option<bool>,
}

impl JebProvider {
    fn new(endpoint: Endpoint, request_timeout_ms: Option<u64>) -> Self {
        let discovery = DEFAULT_REQUEST_TIMEOUT_MS;
        let request = request_timeout_ms.unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        Self {
            connection: JebMcpConnection::new(endpoint.clone(), discovery, request),
            endpoint,
            client_information: std::sync::Mutex::new(None),
        }
    }

    fn identity(&self, version: Option<&str>) -> EvidenceProvider {
        EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, version.map(str::to_owned))
    }

    /// Probe the running JEB client without opening a project.
    ///
    /// Compatibility owner: `inspectAvailability`. Returns a `ProviderAvailability`
    /// JSON value for the binary-session owner.
    pub fn availability(&self, cancellation: &Cancellation) -> Value {
        match self.inspect_available(cancellation) {
            Ok(value) => value,
            Err(reason) => json!({
                "status": "unavailable",
                "code": "not_configured",
                "reason": reason,
                "diagnostics": { "endpoint": self.endpoint.href() },
            }),
        }
    }

    fn inspect_available(&self, cancellation: &Cancellation) -> Result<Value, String> {
        let tools = self
            .connection
            .list_tools(cancellation)
            .map_err(|failure| physical_message(&failure))?;
        let information = self
            .refresh_client_information("inspect_jeb_client", cancellation)
            .map_err(|error| error.user_message())?;
        let supported: Vec<&str> = JEB_ENGINE_TOOLS
            .iter()
            .filter(|(_, engine_tool)| tools.iter().any(|tool| tool == engine_tool))
            .map(|(operation, _)| *operation)
            .collect();
        Ok(json!({
            "status": "available",
            "code": null,
            "reason": null,
            "supportedOperations": supported,
            "diagnostics": {
                "endpoint": self.endpoint.href(),
                "engine_version": information.version,
            },
        }))
    }

    /// Release engine connection state; the JEB client itself keeps running.
    ///
    /// Compatibility owner: `close`. Failed cleanup retains the resources.
    pub fn close(&self, cancellation: &Cancellation) -> Result<(), AnalysisError> {
        match self.connection.close(cancellation) {
            Ok(()) => Ok(()),
            Err(resources) => Err(crate::common::errors::provider_cleanup(
                PROVIDER_ID,
                "close_jeb_connection",
                resources,
                crate::common::errors::object(json!({
                    "reason": "JEB MCP connection cleanup failed",
                })),
            )),
        }
    }

    /// Execute one validated caller-selected request.
    ///
    /// Compatibility owner: `execute` + `#dispatch`.
    pub fn execute(
        &self,
        operation: &str,
        input: &Value,
        cancellation: &Cancellation,
    ) -> Result<Execution, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let result = match operation {
            "inspect_jeb_client" => self.inspect_client(cancellation),
            "open_jeb_project" => self.open_project(input, cancellation),
            "list_jeb_units" => self.list_units(input, cancellation),
            "decompile_jeb_item" => self.decompile_item(input, cancellation),
            other => Err(AnalysisError::capability_unavailable(
                PROVIDER_ID,
                other,
                "Unsupported JEB operation",
            )),
        };
        result.map_err(|error| self.provider_failure(operation, error))
    }

    /// `get_client_information`, caching and parsing the success envelope.
    fn refresh_client_information(
        &self,
        operation: &str,
        cancellation: &Cancellation,
    ) -> Result<ClientInformation, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let payload = self
            .connection
            .call("get_client_information", Map::new(), cancellation)
            .map_err(|failure| self.physical_failure(operation, failure))?;
        let object = self.require_success(&payload, operation)?;
        let information = ClientInformation {
            version: object
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_owned),
            gui_client: object.get("gui_client").and_then(Value::as_bool),
        };
        *self
            .client_information
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(information.clone());
        Ok(information)
    }

    /// `engine` observation for an operation, using cached client information.
    fn engine(
        &self,
        operation: &str,
        cancellation: &Cancellation,
    ) -> Result<(EngineObservation, Option<String>), AnalysisError> {
        let cached = self
            .client_information
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let information = match cached {
            Some(information) => information,
            None => self.refresh_client_information(operation, cancellation)?,
        };
        let version = information.version.clone();
        Ok((
            EngineObservation {
                name: "jeb".to_owned(),
                version: version.clone(),
                endpoint: self.endpoint.href().to_owned(),
                gui_client: information.gui_client,
            },
            version,
        ))
    }

    fn inspect_client(&self, cancellation: &Cancellation) -> Result<Execution, AnalysisError> {
        let payload = self
            .connection
            .call("get_client_information", Map::new(), cancellation)
            .map_err(|failure| self.physical_failure("inspect_jeb_client", failure))?;

        // Extract owned facts, dropping the borrow before `payload` moves into
        // the execution as its raw result.
        let (version, version_present, gui_client, startup_ts, message) = {
            let object = self.require_success(&payload, "inspect_jeb_client")?;
            (
                object
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                object.get("version").is_some(),
                object.get("gui_client").and_then(Value::as_bool),
                object.get("startup_ts").and_then(Value::as_u64),
                object
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
        };

        *self
            .client_information
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ClientInformation {
            version: version.clone(),
            gui_client,
        });

        let result = json!({
            "engine": {
                "name": "jeb",
                "version": version,
                "endpoint": self.endpoint.href(),
                "gui_client": gui_client,
            },
            "startup_ts": startup_ts,
            "message": message,
        });
        let limitations = if version_present {
            Vec::new()
        } else {
            vec!["The engine did not report its version.".to_owned()]
        };
        Ok(self.execution(result, version.as_deref(), payload, limitations))
    }

    fn open_project(
        &self,
        input: &Value,
        cancellation: &Cancellation,
    ) -> Result<Execution, AnalysisError> {
        let path = input
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut arguments = Map::new();
        arguments.insert("file_path".to_owned(), Value::String(path.to_owned()));
        let payload = self
            .connection
            .call("open_project", arguments, cancellation)
            .map_err(|failure| self.physical_failure("open_jeb_project", failure))?;

        let (input_files, units, name, creation_datetime) = {
            let opened = self.require_success(&payload, "open_jeb_project")?;
            let input_files = self.require_input_files(opened, "open_jeb_project")?;
            let units = self.require_units(opened, "open_jeb_project")?;
            let name = opened
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let creation_datetime = opened
                .get("creation_datetime")
                .and_then(Value::as_str)
                .map(str::to_owned);
            (input_files, units, name, creation_datetime)
        };

        let (engine, version) = self.engine("open_jeb_project", cancellation)?;
        let result = json!({
            "engine": engine.to_value(),
            "project_name": name,
            "creation_datetime": creation_datetime,
            "input_files": input_files,
            "units": units,
        });
        let limitations = vec![
            "JEB resolves and analyzes the artifact on the engine host; REA did not open the target itself."
                .to_owned(),
        ];
        Ok(self.execution(result, version.as_deref(), payload, limitations))
    }

    fn list_units(
        &self,
        input: &Value,
        cancellation: &Cancellation,
    ) -> Result<Execution, AnalysisError> {
        let count = input.get("count").and_then(Value::as_u64).unwrap_or(100);
        let index = input.get("index").and_then(Value::as_u64).unwrap_or(0);
        let filter = input
            .get("filter")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let parent_unit_path = input
            .get("parent_unit_path")
            .and_then(Value::as_str)
            .map(str::to_owned);

        let mut arguments = Map::new();
        arguments.insert("count".to_owned(), Value::from(count));
        arguments.insert("index".to_owned(), Value::from(index));
        if let Some(filter) = &filter {
            arguments.insert("filter".to_owned(), Value::String(filter.clone()));
        }
        if let Some(parent) = &parent_unit_path {
            arguments.insert("parent_unit_path".to_owned(), Value::String(parent.clone()));
        }

        let payload = self
            .connection
            .call("list_units", arguments, cancellation)
            .map_err(|failure| self.physical_failure("list_jeb_units", failure))?;
        let units = {
            let listed = self.require_success(&payload, "list_jeb_units")?;
            self.require_units(listed, "list_jeb_units")?
        };
        let unit_count = units.as_array().map(Vec::len).unwrap_or(0) as u64;

        let (engine, version) = self.engine("list_jeb_units", cancellation)?;
        let coverage = if unit_count < count {
            "complete"
        } else {
            "partial"
        };
        let result = json!({
            "engine": engine.to_value(),
            "filter": filter,
            "parent_unit_path": parent_unit_path,
            "index": index,
            "count": count,
            "units": units,
            "coverage": coverage,
        });
        let limitations = vec![
            "The engine caps unit pages at 100; a full page means more units may exist.".to_owned(),
        ];
        Ok(self.execution(result, version.as_deref(), payload, limitations))
    }

    fn decompile_item(
        &self,
        input: &Value,
        cancellation: &Cancellation,
    ) -> Result<Execution, AnalysisError> {
        let item_address = input
            .get("item_address")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let item_kind = input
            .get("item_kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let unit_path = input
            .get("unit_path")
            .and_then(Value::as_str)
            .map(str::to_owned);

        let mut arguments = Map::new();
        arguments.insert(
            "item_address".to_owned(),
            Value::String(item_address.clone()),
        );
        arguments.insert("item_kind".to_owned(), Value::String(item_kind.clone()));
        if let Some(unit_path) = &unit_path {
            arguments.insert("unit_path".to_owned(), Value::String(unit_path.clone()));
        }

        let payload = self
            .connection
            .call("decompile_code_item", arguments, cancellation)
            .map_err(|failure| self.physical_failure("decompile_jeb_item", failure))?;
        let text = {
            let decompiled = self.require_success(&payload, "decompile_jeb_item")?;
            decompiled
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AnalysisError::protocol("JEB omitted or malformed required observation fields")
                })?
                .to_owned()
        };

        let (engine, version) = self.engine("decompile_jeb_item", cancellation)?;
        let result = json!({
            "engine": engine.to_value(),
            "unit_path": unit_path,
            "item_address": item_address,
            "item_kind": item_kind,
            "text": text,
        });
        let limitations = if unit_path.is_none() {
            vec![
                "The engine selected the project's first code unit implicitly; the effective unit identity is unknown."
                    .to_owned(),
            ]
        } else {
            Vec::new()
        };
        Ok(self.execution(result, version.as_deref(), payload, limitations))
    }

    /// Build an `AnalysisExecution` with engine provenance.
    fn execution(
        &self,
        result: Value,
        version: Option<&str>,
        raw_result: Value,
        limitations: Vec<String>,
    ) -> Execution {
        let mut execution = Execution::new(result, self.identity(version));
        execution.raw_result = Some(raw_result);
        execution.limitations = limitations;
        execution
    }

    /// `#requireSuccess`: reject non-object envelopes and refusals.
    fn require_success<'a>(
        &self,
        payload: &'a Value,
        operation: &str,
    ) -> Result<&'a Map<String, Value>, AnalysisError> {
        let Some(object) = payload.as_object() else {
            return Err(AnalysisError::protocol(
                "JEB MCP returned a non-object envelope; no observation can be established",
            ));
        };
        match object.get("success").and_then(Value::as_bool) {
            Some(false) => Err(AnalysisError::unsupported_target(
                operation,
                self.endpoint.href(),
                refusal_reason(payload, "The engine refused the request"),
            )),
            Some(true) => Ok(object),
            None => Err(AnalysisError::protocol(
                "JEB MCP omitted its success field; no observation can be established",
            )),
        }
    }

    /// Validate the `input_files` array exactly as the provider's Zod schema.
    fn require_input_files(
        &self,
        object: &Map<String, Value>,
        operation: &str,
    ) -> Result<Value, AnalysisError> {
        let Some(array) = object.get("input_files").and_then(Value::as_array) else {
            return Err(self.malformed_observation(operation));
        };
        let mut files = Vec::with_capacity(array.len());
        for entry in array {
            let file_name = entry.get("file_name").and_then(Value::as_str);
            let file_size = entry.get("file_size").and_then(Value::as_u64);
            let hash = entry.get("contents_sha256_hash").and_then(Value::as_str);
            match (file_name, file_size, hash) {
                (Some(file_name), Some(file_size), Some(hash)) => {
                    files.push(json!({
                        "file_name": file_name,
                        "file_size": file_size,
                        "contents_sha256_hash": hash,
                    }));
                }
                _ => return Err(self.malformed_observation(operation)),
            }
        }
        Ok(Value::Array(files))
    }

    /// Validate the `units` array (`{ unit_path, unit_type }`).
    fn require_units(
        &self,
        object: &Map<String, Value>,
        operation: &str,
    ) -> Result<Value, AnalysisError> {
        let Some(array) = object.get("units").and_then(Value::as_array) else {
            return Err(self.malformed_observation(operation));
        };
        let mut units = Vec::with_capacity(array.len());
        for entry in array {
            let unit_path = entry.get("unit_path").and_then(Value::as_str);
            let unit_type = entry.get("unit_type").and_then(Value::as_str);
            match (unit_path, unit_type) {
                (Some(unit_path), Some(unit_type)) => {
                    units.push(json!({ "unit_path": unit_path, "unit_type": unit_type }));
                }
                _ => return Err(self.malformed_observation(operation)),
            }
        }
        Ok(Value::Array(units))
    }

    fn malformed_observation(&self, _operation: &str) -> AnalysisError {
        AnalysisError::protocol("JEB omitted or malformed required observation fields")
    }

    /// Map a physical transport failure to the typed provider failure.
    fn physical_failure(&self, operation: &str, failure: PhysicalFailure) -> AnalysisError {
        match failure {
            PhysicalFailure::Timeout => AnalysisError::timeout(operation, self.request_timeout()),
            PhysicalFailure::Cancelled(_) => AnalysisError::cancelled(operation),
            PhysicalFailure::Protocol(message) => AnalysisError::protocol(message),
            PhysicalFailure::Transport(error) => {
                self.capability_unavailable(operation, error.message())
            }
        }
    }

    fn capability_unavailable(&self, operation: &str, reason: String) -> AnalysisError {
        AnalysisError::capability_unavailable(PROVIDER_ID, operation, reason).with_user_message(
            format!(
                "Start a JEB client serving MCP (default {DEFAULT_JEB_MCP_ENDPOINT}) or set REA_JEB_MCP_URL to the running endpoint."
            ),
        )
    }

    fn request_timeout(&self) -> u64 {
        DEFAULT_REQUEST_TIMEOUT_MS
    }

    /// `#providerFailure`: final classification of a dispatch error.
    ///
    /// Typed `AnalysisError`s pass through unchanged; a physical failure not
    /// already classified becomes a capability-unavailable error with the
    /// start-a-client remediation.
    fn provider_failure(&self, operation: &str, error: AnalysisError) -> AnalysisError {
        match &error.kind {
            ErrorKind::Cancelled { .. }
            | ErrorKind::Timeout { .. }
            | ErrorKind::Protocol { .. }
            | ErrorKind::UnsupportedTarget { .. }
            | ErrorKind::CapabilityUnavailable { .. }
            | ErrorKind::ProviderAdapter { .. }
            | ErrorKind::Input { .. } => error,
            _ => self.capability_unavailable(operation, error.user_message()),
        }
    }
}

/// `engine` observation (`name`, `version`, `endpoint`, `gui_client`).
struct EngineObservation {
    name: String,
    version: Option<String>,
    endpoint: String,
    gui_client: Option<bool>,
}

impl EngineObservation {
    fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "version": self.version,
            "endpoint": self.endpoint,
            "gui_client": self.gui_client,
        })
    }
}

/// `refusalReason(payload, fallback)`: the failure envelope's best message.
fn refusal_reason(payload: &Value, fallback: &str) -> String {
    let Some(object) = payload.as_object() else {
        return fallback.to_owned();
    };
    if object.get("success").and_then(Value::as_bool) != Some(false) {
        return fallback.to_owned();
    }
    let error = object.get("error").and_then(Value::as_object);
    let reason = error
        .and_then(|error| error.get("message").and_then(Value::as_str))
        .or_else(|| object.get("message").and_then(Value::as_str))
        .or_else(|| error.and_then(|error| error.get("code").and_then(Value::as_str)));
    match reason {
        Some(reason) if !reason.is_empty() => reason.to_owned(),
        _ => fallback.to_owned(),
    }
}

/// Human-readable text for a physical connection failure.
fn physical_message(failure: &PhysicalFailure) -> String {
    match failure {
        PhysicalFailure::Timeout => "JEB MCP request timed out".to_owned(),
        PhysicalFailure::Cancelled(reason) => reason.clone(),
        PhysicalFailure::Protocol(message) => message.clone(),
        PhysicalFailure::Transport(error) => error.message(),
    }
}
