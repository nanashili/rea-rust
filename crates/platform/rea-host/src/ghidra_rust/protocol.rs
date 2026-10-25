//! Framing and bounded request construction for the optional Rust Ghidra worker.
//!
//! This module deliberately owns only the worker wire contract. Process
//! launching, cancellation, and provider selection remain with the host and
//! application layers, so callers cannot accidentally turn a protocol helper
//! into an implicit provider choice.

use serde_json::{Map, Value, json};

pub const PROTOCOL_NAME: &str = "rea-ghidra-rust-jsonrpc-lines";
pub const PROTOCOL_VERSION: u32 = 2;
pub const WORKER_ARGUMENT: &str = "--rea-rust-ghidra-worker";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BATCH_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_BATCH_SIZE: usize = 64;
pub const MAX_SELECTOR_BYTES: usize = 4 * 1024;
pub const MAX_FUNCTION_PAGE: usize = 256;
pub const MAX_RESOLUTION_SELECTORS: usize = 64;
pub const MAX_NAME_BYTES: usize = 4 * 1024;
pub const MAX_DIGEST_BYTES: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
pub const MAX_COUNT: usize = 1_000_000;
pub const MAX_PSEUDOCODE_BYTES: usize = 512 * 1024;
pub const MAX_CAPABILITY_BYTES: usize = 64;
pub const MAX_LIMITATION_BYTES: usize = 4 * 1024;
pub const CACHE_ID: &str = "ghidra-rust-268c3a4-v13";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRequest {
    id: u64,
    method: String,
    params: Value,
}

impl WorkerRequest {
    pub fn new(id: u64, method: impl Into<String>, params: Value) -> Result<Self, String> {
        if !(1..=MAX_SAFE_INTEGER).contains(&id) {
            return Err("worker request id must be a safe positive integer".into());
        }

        let method = method.into();
        if method.is_empty() || method.len() > 64 {
            return Err("worker method must contain 1..=64 bytes".into());
        }

        if !params.is_object() {
            return Err("worker request params must be an object".into());
        }

        Ok(Self { id, method, params })
    }

    pub fn batch_decompile(id: u64, addresses: &[String]) -> Result<Self, String> {
        Self::batch_decompile_with_cache(id, addresses, false)
    }

    pub fn batch_decompile_with_cache(
        id: u64,
        addresses: &[String],
        cache_only: bool,
    ) -> Result<Self, String> {
        if addresses.len() > MAX_BATCH_SIZE {
            return Err("worker batches accept at most 64 addresses".into());
        }

        for address in addresses {
            if !is_worker_address(address) {
                return Err("worker address selector is not canonical".into());
            }
        }

        let mut params = Map::new();
        params.insert("addresses".into(), json!(addresses));
        if cache_only {
            params.insert("cache_only".into(), Value::Bool(true));
        }
        Self::new(id, "batch_decompile", Value::Object(params))
    }

    pub fn info(id: u64) -> Result<Self, String> {
        Self::new(id, "info", json!({}))
    }

    pub fn open(id: u64, path: &str, target_sha256: &str) -> Result<Self, String> {
        bounded_text(path, MAX_SELECTOR_BYTES, "worker target path")?;
        require_nonempty(path, "worker target path")?;
        validate_digest(target_sha256, "target_sha256")?;
        Self::new(
            id,
            "open",
            json!({ "path": path, "target_sha256": target_sha256 }),
        )
    }

    pub fn functions(id: u64, offset: usize, limit: usize) -> Result<Self, String> {
        if limit == 0 || limit > MAX_FUNCTION_PAGE {
            return Err("worker function page limit must be 1..=256".into());
        }
        Self::new(id, "functions", json!({ "offset": offset, "limit": limit }))
    }

    pub fn resolve_functions(id: u64, selectors: &[String]) -> Result<Self, String> {
        if selectors.is_empty() || selectors.len() > MAX_RESOLUTION_SELECTORS {
            return Err("worker resolution accepts 1..=64 selectors".into());
        }
        for selector in selectors {
            bounded_text(selector, MAX_SELECTOR_BYTES, "worker selector")?;
            require_nonempty(selector, "worker selector")?;
        }
        Self::new(id, "resolve_functions", json!({ "selectors": selectors }))
    }

    pub fn segments(id: u64) -> Result<Self, String> {
        Self::new(id, "segments", json!({}))
    }

    pub fn checkpoint(id: u64) -> Result<Self, String> {
        Self::new(id, "checkpoint", json!({}))
    }

    pub fn close(id: u64) -> Result<Self, String> {
        Self::new(id, "close", json!({}))
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn encode_line(&self) -> Result<Vec<u8>, String> {
        let frame = json!({
            "jsonrpc": "2.0",
            "id": self.id,
            "method": self.method,
            "params": self.params,
        });
        let mut encoded = serde_json::to_vec(&frame).map_err(|error| error.to_string())?;
        if encoded.len() + 1 > MAX_REQUEST_BYTES {
            return Err("worker request exceeds the 64 KiB frame limit".into());
        }
        encoded.push(b'\n');
        Ok(encoded)
    }
}

fn bounded_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.len() > maximum {
        return Err(format!("{label} exceeds the bounded size"));
    }
    Ok(())
}

fn require_nonempty(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != MAX_DIGEST_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be a 64-character hexadecimal digest"));
    }
    Ok(())
}

fn is_worker_address(value: &str) -> bool {
    let Some(digits) = value.strip_prefix("0x") else {
        return false;
    };
    !digits.is_empty()
        && digits.len() <= 16
        && (digits.len() == 1 || !digits.starts_with('0'))
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, PartialEq)]
pub enum WorkerFrame {
    Reply {
        id: u64,
        result: Value,
    },
    Error {
        id: u64,
        code: i64,
        message: String,
        error_code: Option<String>,
    },
    Progress {
        label: String,
        completed: usize,
        total: Option<usize>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerProtocolError {
    Malformed(String),
    RequestFailed {
        id: u64,
        code: i64,
        message: String,
        error_code: Option<String>,
    },
    UnexpectedReply {
        expected: u64,
        actual: u64,
    },
}

impl std::fmt::Display for WorkerProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(message) => formatter.write_str(message),
            Self::RequestFailed { code, message, .. } => {
                write!(formatter, "worker request failed with {code}: {message}")
            }
            Self::UnexpectedReply { expected, actual } => {
                write!(
                    formatter,
                    "worker reply id {actual} did not match {expected}"
                )
            }
        }
    }
}

impl std::error::Error for WorkerProtocolError {}

#[derive(Clone, Debug, PartialEq)]
pub struct WorkerInfo {
    pub engine: Value,
    pub provider: String,
    pub worker_protocol_version: u32,
    pub worker_protocol_name: String,
    pub cache_id: String,
    pub snapshot_schema: u32,
    pub worker_sha256: String,
    pub config_identity: String,
    pub inventory_frozen: bool,
    pub memory_limit_mib: Option<u64>,
    pub timeout_ms: u64,
    pub capabilities: Vec<String>,
    pub target_sha256: Option<String>,
    pub inventory_sha256: Option<String>,
    pub indexed_functions: Option<usize>,
    pub total: Option<usize>,
    pub preparation: Option<String>,
    pub language: Option<String>,
    pub limitations: Vec<String>,
}

impl WorkerInfo {
    pub fn require_target(&self, target_sha256: &str) -> Result<(), WorkerProtocolError> {
        if self.target_sha256.as_deref() == Some(target_sha256) {
            return Ok(());
        }
        Err(WorkerProtocolError::Malformed(
            "worker info target identity did not match the opened target".into(),
        ))
    }

    pub fn require_inventory(&self, inventory_sha256: &str) -> Result<(), WorkerProtocolError> {
        if self.inventory_sha256.as_deref() == Some(inventory_sha256) {
            return Ok(());
        }
        Err(WorkerProtocolError::Malformed(
            "worker info inventory identity did not match the session".into(),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerFunction {
    pub address: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerFunctionPage {
    pub items: Vec<WorkerFunction>,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub indexed_functions: usize,
    pub total: usize,
    pub inventory_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerFunctionResolution {
    pub selector: String,
    pub status: String,
    pub address: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerResolution {
    pub items: Vec<WorkerFunctionResolution>,
    pub inventory_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerSegment {
    pub name: String,
    pub address: String,
    pub end: String,
    pub executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerSegments {
    pub items: Vec<WorkerSegment>,
    pub coverage: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerAcknowledgement {
    pub saved: Option<bool>,
    pub closed: Option<bool>,
}

pub fn decode_info(
    frame: WorkerFrame,
    expected_id: u64,
) -> Result<WorkerInfo, WorkerProtocolError> {
    decode_result(frame, expected_id, parse_info)
}

pub fn decode_function_page(
    frame: WorkerFrame,
    expected_id: u64,
) -> Result<WorkerFunctionPage, WorkerProtocolError> {
    decode_result(frame, expected_id, parse_function_page)
}

pub fn decode_resolution(
    frame: WorkerFrame,
    expected_id: u64,
) -> Result<WorkerResolution, WorkerProtocolError> {
    decode_result(frame, expected_id, parse_resolution)
}

pub fn decode_segments(
    frame: WorkerFrame,
    expected_id: u64,
) -> Result<WorkerSegments, WorkerProtocolError> {
    decode_result(frame, expected_id, parse_segments)
}

pub fn decode_checkpoint(
    frame: WorkerFrame,
    expected_id: u64,
) -> Result<WorkerAcknowledgement, WorkerProtocolError> {
    decode_result(frame, expected_id, parse_checkpoint)
}

pub fn decode_close(
    frame: WorkerFrame,
    expected_id: u64,
) -> Result<WorkerAcknowledgement, WorkerProtocolError> {
    decode_result(frame, expected_id, parse_close)
}

fn decode_result<T>(
    frame: WorkerFrame,
    expected_id: u64,
    parse: fn(&Value) -> Result<T, String>,
) -> Result<T, WorkerProtocolError> {
    let result = match frame {
        WorkerFrame::Reply { id, result } if id == expected_id => result,
        WorkerFrame::Reply { id, .. } => {
            return Err(WorkerProtocolError::UnexpectedReply {
                expected: expected_id,
                actual: id,
            });
        }
        WorkerFrame::Error {
            id,
            code,
            message,
            error_code,
        } => {
            return Err(WorkerProtocolError::RequestFailed {
                id,
                code,
                message,
                error_code,
            });
        }
        WorkerFrame::Progress { .. } => {
            return Err(WorkerProtocolError::Malformed(
                "progress is not a request reply".into(),
            ));
        }
    };
    parse(&result).map_err(WorkerProtocolError::Malformed)
}

pub struct LineDecoder {
    pending: Vec<u8>,
}

impl Default for LineDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl LineDecoder {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<WorkerFrame>, String> {
        if self.pending.len().saturating_add(bytes.len()) > MAX_FRAME_BYTES {
            return Err("worker output exceeds the 8 MiB frame limit".into());
        }
        self.pending.extend_from_slice(bytes);

        let mut frames = Vec::new();
        while let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=index).collect();
            frames.push(parse_frame(&line[..line.len() - 1])?);
        }
        Ok(frames)
    }

    pub fn finish(self) -> Result<(), String> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err("worker output ended with a truncated frame".into())
        }
    }
}

fn parse_frame(bytes: &[u8]) -> Result<WorkerFrame, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "worker frame must be an object".to_owned())?;

    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("worker frame must use JSON-RPC 2.0".into());
    }

    if object.get("method").and_then(Value::as_str) == Some("analysis/progress") {
        reject_unknown_fields(object, &["jsonrpc", "method", "params"])?;
        return parse_progress(object);
    }

    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "worker reply is missing a numeric id".to_owned())?;
    if id == 0 || id > MAX_SAFE_INTEGER {
        return Err("worker reply id must be a safe positive integer".into());
    }
    if let Some(result) = object.get("result") {
        reject_unknown_fields(object, &["jsonrpc", "id", "result"])?;
        return Ok(WorkerFrame::Reply {
            id,
            result: result.clone(),
        });
    }

    reject_unknown_fields(object, &["jsonrpc", "id", "error"])?;
    let error = object
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(|| "worker reply must contain result or error".to_owned())?;
    if error.get("code").and_then(Value::as_i64) != Some(-32_000) {
        return Err("worker error code is invalid".into());
    }
    let code = -32_000;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| "worker error is missing a message".to_owned())?;
    bounded_text(message, MAX_MESSAGE_BYTES, "worker error message")?;
    reject_unknown_fields(error, &["code", "message", "data"])?;
    let data = error
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| "worker error is missing data".to_owned())?;
    reject_unknown_fields(data, &["error_code"])?;
    let error_code = error
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("error_code"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if !matches!(
        error_code.as_deref(),
        Some("WORKER_FAILED" | "CACHE_INTEGRITY_FAILED")
    ) {
        return Err("worker error data.error_code is invalid".into());
    }
    Ok(WorkerFrame::Error {
        id,
        code,
        message: message.to_owned(),
        error_code,
    })
}

fn parse_progress(object: &Map<String, Value>) -> Result<WorkerFrame, String> {
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| "worker progress is missing params".to_owned())?;
    reject_unknown_fields(params, &["label", "completed", "total"])?;
    let label = params
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| "worker progress is missing label".to_owned())?;
    bounded_text(label, MAX_MESSAGE_BYTES, "worker progress label")?;
    let completed = params
        .get("completed")
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "worker progress has an invalid completed count".to_owned())?;
    let total = params
        .get("total")
        .filter(|value| !value.is_null())
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .map(|value| {
            usize::try_from(value).map_err(|_| "worker progress total is too large".to_owned())
        })
        .transpose()?;
    if total.is_some_and(|value| completed > value) {
        return Err("worker progress completed count exceeds total".into());
    }
    Ok(WorkerFrame::Progress {
        label: label.to_owned(),
        completed,
        total,
    })
}

fn parse_info(value: &Value) -> Result<WorkerInfo, String> {
    let object = object(value, "info")?;
    reject_unknown_fields(
        object,
        &[
            "engine",
            "provider",
            "worker_protocol_version",
            "worker_protocol_name",
            "cache_id",
            "snapshot_schema",
            "worker_sha256",
            "config_identity",
            "inventory_frozen",
            "memory_limit_mib",
            "timeout_ms",
            "capabilities",
            "target_sha256",
            "inventory_sha256",
            "indexed_functions",
            "total",
            "preparation",
            "language",
            "limitations",
        ],
    )?;
    required(object, "engine")?
        .as_object()
        .ok_or_else(|| "engine must be an object".to_owned())?;
    let preparation = optional_text_field(object, "preparation", MAX_NAME_BYTES)?;
    if preparation
        .as_deref()
        .is_some_and(|value| !matches!(value, "restored" | "loader_inventory"))
    {
        return Err("preparation has an unsupported value".into());
    }
    Ok(WorkerInfo {
        engine: required(object, "engine")?.clone(),
        provider: exact_text_field(object, "provider", "ghidra-rust")?,
        worker_protocol_version: exact_number_field(object, "worker_protocol_version", 2)?,
        worker_protocol_name: exact_text_field(object, "worker_protocol_name", PROTOCOL_NAME)?,
        cache_id: exact_text_field(object, "cache_id", CACHE_ID)?,
        snapshot_schema: exact_number_field(object, "snapshot_schema", 1)?,
        worker_sha256: digest_field(object, "worker_sha256")?,
        config_identity: digest_field(object, "config_identity")?,
        inventory_frozen: bool_field(object, "inventory_frozen")?,
        memory_limit_mib: null_field(object, "memory_limit_mib")?,
        timeout_ms: positive_number_field(object, "timeout_ms")?,
        capabilities: text_array_field(object, "capabilities", 32, MAX_CAPABILITY_BYTES)?,
        target_sha256: optional_digest_field(object, "target_sha256")?,
        inventory_sha256: optional_digest_field(object, "inventory_sha256")?,
        indexed_functions: bounded_optional_number_field(object, "indexed_functions")?,
        total: bounded_optional_number_field(object, "total")?,
        preparation,
        language: optional_text_field(object, "language", MAX_NAME_BYTES)?,
        limitations: optional_text_array_field(object, "limitations", 32, MAX_LIMITATION_BYTES)?,
    })
}

fn parse_function_page(value: &Value) -> Result<WorkerFunctionPage, String> {
    let object = object(value, "functions")?;
    reject_unknown_fields(
        object,
        &[
            "items",
            "offset",
            "next_offset",
            "indexed_functions",
            "total",
            "inventory_sha256",
        ],
    )?;
    let items = required_array(object, "items", MAX_FUNCTION_PAGE)?
        .iter()
        .map(parse_function)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkerFunctionPage {
        items,
        offset: bounded_number_field(object, "offset")?,
        next_offset: bounded_nullable_number_field(object, "next_offset")?,
        indexed_functions: bounded_number_field(object, "indexed_functions")?,
        total: bounded_number_field(object, "total")?,
        inventory_sha256: digest_field(object, "inventory_sha256")?,
    })
}

fn parse_function(value: &Value) -> Result<WorkerFunction, String> {
    let object = object(value, "function")?;
    reject_unknown_fields(object, &["address", "name"])?;
    Ok(WorkerFunction {
        address: address_field(object, "address")?,
        name: text_field(object, "name", MAX_NAME_BYTES)?,
    })
}

fn parse_resolution(value: &Value) -> Result<WorkerResolution, String> {
    let object = object(value, "resolve_functions")?;
    reject_unknown_fields(object, &["items", "inventory_sha256"])?;
    let items = required_array(object, "items", MAX_RESOLUTION_SELECTORS)?
        .iter()
        .map(parse_resolution_item)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkerResolution {
        items,
        inventory_sha256: digest_field(object, "inventory_sha256")?,
    })
}

fn parse_resolution_item(value: &Value) -> Result<WorkerFunctionResolution, String> {
    let object = object(value, "resolution item")?;
    reject_unknown_fields(object, &["selector", "status", "address", "name"])?;
    let status = text_field(object, "status", 16)?;
    if !matches!(status.as_str(), "found" | "not_found" | "ambiguous") {
        return Err("resolution status is invalid".into());
    }
    Ok(WorkerFunctionResolution {
        selector: text_field(object, "selector", MAX_SELECTOR_BYTES)?,
        status,
        address: optional_address_field(object, "address")?,
        name: optional_text_field(object, "name", MAX_NAME_BYTES)?,
    })
}

fn parse_segments(value: &Value) -> Result<WorkerSegments, String> {
    let segments_object = object(value, "segments")?;
    reject_unknown_fields(segments_object, &["items", "coverage"])?;
    let items = required_array(segments_object, "items", 4096)?
        .iter()
        .map(|value| {
            let segment_object = object(value, "segment")?;
            reject_unknown_fields(segment_object, &["name", "address", "end", "executable"])?;
            Ok(WorkerSegment {
                name: text_field(segment_object, "name", MAX_NAME_BYTES)?,
                address: address_field(segment_object, "address")?,
                end: address_field(segment_object, "end")?,
                executable: bool_field(segment_object, "executable")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(WorkerSegments {
        items,
        coverage: text_field(segments_object, "coverage", MAX_NAME_BYTES)?,
    })
}

fn parse_checkpoint(value: &Value) -> Result<WorkerAcknowledgement, String> {
    let object = object(value, "checkpoint")?;
    reject_unknown_fields(object, &["saved"])?;
    if object.get("saved") != Some(&Value::Bool(true)) {
        return Err("checkpoint did not acknowledge saved=true".into());
    }
    Ok(WorkerAcknowledgement {
        saved: Some(true),
        closed: None,
    })
}

fn parse_close(value: &Value) -> Result<WorkerAcknowledgement, String> {
    let object = object(value, "close")?;
    reject_unknown_fields(object, &["saved", "closed"])?;
    if object.get("closed") != Some(&Value::Bool(true)) {
        return Err("close did not acknowledge closed=true".into());
    }
    Ok(WorkerAcknowledgement {
        saved: Some(bool_field(object, "saved")?),
        closed: Some(true),
    })
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<&'a Vec<Value>, String> {
    let values = required(object, name)?
        .as_array()
        .ok_or_else(|| format!("{name} must be an array"))?;
    if values.len() > maximum {
        return Err(format!("{name} exceeds its item limit"));
    }
    Ok(values)
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} result must be an object"))
}

fn required<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, String> {
    object
        .get(name)
        .ok_or_else(|| format!("result is missing {name}"))
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("worker object contains an unknown field".into());
    }
    Ok(())
}

fn text_field(object: &Map<String, Value>, name: &str, maximum: usize) -> Result<String, String> {
    let value = required(object, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be text"))?;
    bounded_text(value, maximum, name)?;
    Ok(value.to_owned())
}

fn optional_text_field(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<Option<String>, String> {
    object
        .get(name)
        .map(|_| text_field(object, name, maximum))
        .transpose()
}

fn text_array_field(
    object: &Map<String, Value>,
    name: &str,
    maximum_items: usize,
    maximum_text: usize,
) -> Result<Vec<String>, String> {
    let values = required(object, name)?
        .as_array()
        .ok_or_else(|| format!("{name} must be an array"))?;
    if values.len() > maximum_items {
        return Err(format!("{name} exceeds its item limit"));
    }
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| format!("{name} contains non-text"))?;
            bounded_text(value, maximum_text, name)?;
            Ok(value.to_owned())
        })
        .collect()
}

fn optional_text_array_field(
    object: &Map<String, Value>,
    name: &str,
    maximum_items: usize,
    maximum_text: usize,
) -> Result<Vec<String>, String> {
    object
        .get(name)
        .map(|_| text_array_field(object, name, maximum_items, maximum_text))
        .transpose()
        .map(|value| value.unwrap_or_default())
}

fn number_field<T>(object: &Map<String, Value>, name: &str) -> Result<T, String>
where
    T: TryFrom<u64>,
{
    let value = required(object, name)?
        .as_u64()
        .ok_or_else(|| format!("{name} must be a nonnegative integer"))?;
    if value > MAX_SAFE_INTEGER {
        return Err(format!("{name} exceeds the safe integer limit"));
    }
    T::try_from(value).map_err(|_| format!("{name} is too large"))
}

fn bounded_number_field(object: &Map<String, Value>, name: &str) -> Result<usize, String> {
    let value = number_field(object, name)?;
    if value > MAX_COUNT {
        return Err(format!("{name} exceeds its count limit"));
    }
    Ok(value)
}

fn positive_number_field(object: &Map<String, Value>, name: &str) -> Result<u64, String> {
    let value = number_field(object, name)?;
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(value)
}

fn optional_number_field<T>(object: &Map<String, Value>, name: &str) -> Result<Option<T>, String>
where
    T: TryFrom<u64>,
{
    object
        .get(name)
        .map(|_| number_field(object, name))
        .transpose()
}

fn bounded_optional_number_field(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<usize>, String> {
    optional_number_field(object, name)?.map_or(Ok(None), |value| {
        if value > MAX_COUNT {
            Err(format!("{name} exceeds its count limit"))
        } else {
            Ok(Some(value))
        }
    })
}

fn exact_number_field<T>(object: &Map<String, Value>, name: &str, expected: T) -> Result<T, String>
where
    T: TryFrom<u64> + PartialEq + Copy,
{
    let value = number_field(object, name)?;
    if value != expected {
        return Err(format!("{name} has an unsupported value"));
    }
    Ok(value)
}

fn exact_text_field(
    object: &Map<String, Value>,
    name: &str,
    expected: &str,
) -> Result<String, String> {
    let value = text_field(object, name, MAX_NAME_BYTES)?;
    if value != expected {
        return Err(format!("{name} has an unsupported value"));
    }
    Ok(value)
}

fn null_field(object: &Map<String, Value>, name: &str) -> Result<Option<u64>, String> {
    if required(object, name)?.is_null() {
        Ok(None)
    } else {
        Err(format!("{name} must be null"))
    }
}

fn nullable_number_field<T>(object: &Map<String, Value>, name: &str) -> Result<Option<T>, String>
where
    T: TryFrom<u64>,
{
    match object.get(name) {
        Some(Value::Null) => Ok(None),
        Some(_) => number_field(object, name).map(Some),
        None => Err(format!("result is missing {name}")),
    }
}

fn bounded_nullable_number_field(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<usize>, String> {
    let value = nullable_number_field(object, name)?;
    value.map_or(Ok(None), |value| {
        if value > MAX_COUNT {
            Err(format!("{name} exceeds its count limit"))
        } else {
            Ok(Some(value))
        }
    })
}

fn bool_field(object: &Map<String, Value>, name: &str) -> Result<bool, String> {
    required(object, name)?
        .as_bool()
        .ok_or_else(|| format!("{name} must be boolean"))
}

fn digest_field(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    let value = text_field(object, name, MAX_DIGEST_BYTES)?;
    validate_digest(&value, name)?;
    Ok(value)
}

fn optional_digest_field(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    object
        .get(name)
        .map(|_| digest_field(object, name))
        .transpose()
}

fn address_field(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    let value = text_field(object, name, 18)?;
    let digits = value.strip_prefix("0x").unwrap_or("");
    if digits.is_empty()
        || digits.len() > 16
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} is not a worker address"));
    }
    Ok(value)
}

fn optional_address_field(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    match object.get(name) {
        Some(Value::Null) => Ok(None),
        Some(_) => address_field(object, name).map(Some),
        None => Err(format!("result is missing {name}")),
    }
}
