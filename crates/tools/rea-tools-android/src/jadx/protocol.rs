//! Pinned upstream wire schemas and envelope parsing.
//!
//! Compatibility owner: `src/android/JadxProtocol.ts` and the DEX descriptor
//! in `src/domain/android/androidAnalysis.ts`. Each schema validates the exact
//! shape the TS Zod schema accepts; a violation is an `AnalysisOutputError`.

use rea_core::analysis_error::AnalysisError;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Why an upstream payload could not be adopted.
#[derive(Debug)]
pub enum ProtocolError {
    /// Schema violation (`AnalysisOutputError`, pinned protocol).
    Schema(String),
}

impl ProtocolError {
    pub fn into_output(self, operation: &str) -> AnalysisError {
        match self {
            Self::Schema(reason) => AnalysisError::output(operation, reason),
        }
    }
}

fn schema(reason: impl Into<String>) -> ProtocolError {
    ProtocolError::Schema(reason.into())
}

/// `dexDescriptorSchema`: a DEX prototype string.
pub fn is_dex_descriptor(value: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let regex = CELL.get_or_init(|| {
        Regex::new(r"^\((?:\[*(?:[ZBSCIJFD]|L[^;()]+;))*\)(?:V|\[*(?:[ZBSCIJFD]|L[^;()]+;))$")
            .expect("valid DEX descriptor regex")
    });
    regex.is_match(value)
}

fn as_object(value: &Value) -> Result<&serde_json::Map<String, Value>, ProtocolError> {
    value
        .as_object()
        .ok_or_else(|| schema("expected a JSON object"))
}

fn get_str<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, ProtocolError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| schema(format!("missing string field {key}")))
}

fn get_count(object: &serde_json::Map<String, Value>, key: &str) -> Result<u64, ProtocolError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| schema(format!("missing nonnegative integer field {key}")))
}

fn get_bool(object: &serde_json::Map<String, Value>, key: &str) -> Result<bool, ProtocolError> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| schema(format!("missing boolean field {key}")))
}

fn get_i64(object: &serde_json::Map<String, Value>, key: &str) -> Result<i64, ProtocolError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| schema(format!("missing integer field {key}")))
}

fn get_array<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a Vec<Value>, ProtocolError> {
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| schema(format!("missing array field {key}")))
}

fn string_vec(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, ProtocolError> {
    get_array(object, key)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| schema(format!("{key} entries must be strings")))
        })
        .collect()
}

/// `jadxRuntimeSchema`.
#[derive(Clone, Debug)]
pub struct JadxRuntime {
    pub engine_reported_version: String,
    pub max_heap_bytes: u64,
}

pub fn parse_runtime(value: &Value) -> Result<JadxRuntime, ProtocolError> {
    let object = as_object(value)?;
    let engine_reported_version = get_str(object, "engine_reported_version")?.to_owned();
    if engine_reported_version.is_empty() {
        return Err(schema("engine_reported_version must be non-empty"));
    }
    let max_heap_bytes = object
        .get("max_heap_bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| schema("max_heap_bytes must be a positive safe integer"))?;
    if object
        .get("available_processors")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .is_none()
    {
        return Err(schema("available_processors must be a positive integer"));
    }
    if get_str(object, "java_version")?.is_empty() {
        return Err(schema("java_version must be non-empty"));
    }
    if get_str(object, "metadata_scope")? != "parsed_members" {
        return Err(schema("metadata_scope must be parsed_members"));
    }
    Ok(JadxRuntime {
        engine_reported_version,
        max_heap_bytes,
    })
}

/// `jadxLoadSchema`.
#[derive(Clone, Debug)]
pub struct JadxLoad {
    pub apk_path: String,
    pub class_count: u64,
    pub resource_count: u64,
}

pub fn parse_load(value: &Value) -> Result<JadxLoad, ProtocolError> {
    let object = as_object(value)?;
    if get_str(object, "state")? != "LOADED" {
        return Err(schema("load state must be LOADED"));
    }
    let apk_path = get_str(object, "apk_path")?.to_owned();
    let class_count = get_count(object, "class_count")?;
    let resource_count = get_count(object, "resource_count")?;
    if object.get("threads").and_then(Value::as_u64) != Some(1) {
        return Err(schema("threads must be 1"));
    }
    if object.get("resources").and_then(Value::as_str) != Some("full") {
        return Err(schema("resources must be full"));
    }
    Ok(JadxLoad {
        apk_path,
        class_count,
        resource_count,
    })
}

/// `jadxAppSchema`.
#[derive(Clone, Debug)]
pub struct JadxApp {
    pub package: String,
    pub version_name: String,
    pub version_code: String,
    pub min_sdk: String,
    pub target_sdk: String,
    pub permissions: Vec<String>,
}

pub fn parse_app(value: &Value) -> Result<JadxApp, ProtocolError> {
    let object = as_object(value)?;
    Ok(JadxApp {
        package: get_str(object, "package")?.to_owned(),
        version_name: get_str(object, "version_name")?.to_owned(),
        version_code: get_str(object, "version_code")?.to_owned(),
        min_sdk: get_str(object, "min_sdk")?.to_owned(),
        target_sdk: get_str(object, "target_sdk")?.to_owned(),
        permissions: string_vec(object, "permissions")?,
    })
}

/// `jadxClassPageSchema`.
#[derive(Clone, Debug)]
pub struct JadxClassPage {
    pub total_classes: u64,
    pub next_offset: u64,
    pub offset: u64,
    pub limit: u64,
    pub items: Vec<String>,
}

pub fn parse_class_page(value: &Value) -> Result<JadxClassPage, ProtocolError> {
    let object = as_object(value)?;
    if object.get("scope").and_then(Value::as_str) != Some("top_level") {
        return Err(schema("class page scope must be top_level"));
    }
    Ok(JadxClassPage {
        total_classes: get_count(object, "total_classes")?,
        next_offset: get_count(object, "next_offset")?,
        offset: get_count(object, "offset")?,
        limit: get_count(object, "limit")?,
        items: string_vec(object, "items")?,
    })
}

/// A method row inside a class summary.
#[derive(Clone, Debug)]
pub struct JadxMethodRow {
    pub name: String,
    pub signature: String,
    pub dex_descriptor: String,
    pub is_constructor: bool,
}

/// A field row inside a class summary.
#[derive(Clone, Debug)]
pub struct JadxFieldRow {
    pub name: String,
    pub field_type: String,
}

/// `jadxClassSchema`.
#[derive(Clone, Debug)]
pub struct JadxClass {
    pub full_name: String,
    pub method_count: u64,
    pub field_count: u64,
    pub inner_class_count: u64,
    pub methods: Vec<JadxMethodRow>,
    pub fields: Vec<JadxFieldRow>,
    pub inner_classes: Vec<String>,
}

pub fn parse_class(value: &Value) -> Result<JadxClass, ProtocolError> {
    let object = as_object(value)?;
    let methods = get_array(object, "methods")?
        .iter()
        .map(|entry| {
            let method = as_object(entry)?;
            let dex_descriptor = get_str(method, "dex_descriptor")?.to_owned();
            if !is_dex_descriptor(&dex_descriptor) {
                return Err(schema("method dex_descriptor is malformed"));
            }
            get_i64(method, "def_pos")?;
            Ok(JadxMethodRow {
                name: get_str(method, "name")?.to_owned(),
                signature: get_str(method, "signature")?.to_owned(),
                dex_descriptor,
                is_constructor: get_bool(method, "is_constructor")?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fields = get_array(object, "fields")?
        .iter()
        .map(|entry| {
            let field = as_object(entry)?;
            get_i64(field, "def_pos")?;
            Ok(JadxFieldRow {
                name: get_str(field, "name")?.to_owned(),
                field_type: get_str(field, "type")?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JadxClass {
        full_name: get_str(object, "full_name")?.to_owned(),
        method_count: get_count(object, "method_count")?,
        field_count: get_count(object, "field_count")?,
        inner_class_count: get_count(object, "inner_class_count")?,
        methods,
        fields,
        inner_classes: string_vec(object, "inner_classes")?,
    })
}

/// `jadxMethodSchema` (method body).
#[derive(Clone, Debug)]
pub struct JadxMethodBody {
    pub class_name: String,
    pub method_name: String,
    pub overload_index: u64,
    pub overload_count: u64,
    pub dex_descriptor: String,
    pub mode: String,
    pub fell_back: bool,
    pub markers: Vec<String>,
    pub body: String,
}

pub fn parse_method_body(value: &Value) -> Result<JadxMethodBody, ProtocolError> {
    let object = as_object(value)?;
    let dex_descriptor = get_str(object, "dex_descriptor")?.to_owned();
    if !is_dex_descriptor(&dex_descriptor) {
        return Err(schema("method dex_descriptor is malformed"));
    }
    let mode = get_str(object, "mode")?.to_owned();
    if mode != "java" && mode != "smali" {
        return Err(schema("method mode must be java or smali"));
    }
    // full_name is required by the schema.
    get_str(object, "full_name")?;
    Ok(JadxMethodBody {
        class_name: get_str(object, "class_name")?.to_owned(),
        method_name: get_str(object, "method_name")?.to_owned(),
        overload_index: get_count(object, "overload_index")?,
        overload_count: get_count(object, "overload_count")?,
        dex_descriptor,
        mode,
        fell_back: get_bool(object, "fell_back")?,
        markers: string_vec(object, "markers")?,
        body: get_str(object, "body")?.to_owned(),
    })
}

/// One direct invoke instruction inside a using node.
#[derive(Clone, Debug)]
pub struct DirectInvoke {
    pub dex_entry: String,
    pub source_raw_method_id: String,
    pub dex_code_unit_offset: u64,
    pub dex_method_index: u64,
    pub opcode: String,
}

impl DirectInvoke {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "dex_entry": self.dex_entry,
            "source_raw_method_id": self.source_raw_method_id,
            "dex_code_unit_offset": self.dex_code_unit_offset,
            "dex_method_index": self.dex_method_index,
            "opcode": self.opcode,
        })
    }
}

/// One xref item.
#[derive(Clone, Debug)]
pub struct XrefItem {
    pub kind: String,
    pub name: String,
    pub full_name: String,
    pub containing_class: String,
    pub top_class: String,
    pub direct_invokes_exhaustive: Option<bool>,
    pub direct_invokes: Option<Vec<DirectInvoke>>,
}

/// `jadxXrefsSchema`.
#[derive(Clone, Debug)]
pub struct JadxXrefs {
    pub target: String,
    pub overload_index: Option<u64>,
    pub reported_signature: Option<String>,
    pub total: u64,
    pub count: u64,
    pub items: Vec<XrefItem>,
}

pub fn parse_xrefs(value: &Value) -> Result<JadxXrefs, ProtocolError> {
    let object = as_object(value)?;
    if object.get("resolve_line").and_then(Value::as_bool) != Some(false) {
        return Err(schema("xrefs resolve_line must be false"));
    }
    let overload_index = match object.get("overload_index") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| schema("overload_index must be a nonnegative integer"))?,
        ),
    };
    let reported_signature = match object.get("reported_signature") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| schema("reported_signature must be a string"))?
                .to_owned(),
        ),
    };
    let opcode = Regex::new(r"^INVOKE_").expect("valid opcode regex");
    let items = get_array(object, "items")?
        .iter()
        .map(|entry| {
            let item = as_object(entry)?;
            let direct_invokes_exhaustive = match item.get("direct_invokes_exhaustive") {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_bool()
                        .ok_or_else(|| schema("direct_invokes_exhaustive must be a boolean"))?,
                ),
            };
            let direct_invokes = match item.get("direct_invokes") {
                None | Some(Value::Null) => None,
                Some(Value::Array(entries)) => Some(
                    entries
                        .iter()
                        .map(|entry| {
                            let invoke = as_object(entry)?;
                            let dex_entry = get_str(invoke, "dex_entry")?.to_owned();
                            if dex_entry.is_empty() {
                                return Err(schema("dex_entry must be non-empty"));
                            }
                            let source_raw_method_id =
                                get_str(invoke, "source_raw_method_id")?.to_owned();
                            if source_raw_method_id.is_empty() {
                                return Err(schema("source_raw_method_id must be non-empty"));
                            }
                            let op = get_str(invoke, "opcode")?.to_owned();
                            if !opcode.is_match(&op) {
                                return Err(schema("opcode must start with INVOKE_"));
                            }
                            Ok(DirectInvoke {
                                dex_entry,
                                source_raw_method_id,
                                dex_code_unit_offset: get_count(invoke, "dex_code_unit_offset")?,
                                dex_method_index: get_count(invoke, "dex_method_index")?,
                                opcode: op,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                Some(_) => return Err(schema("direct_invokes must be an array")),
            };
            get_i64(item, "def_pos")?;
            Ok(XrefItem {
                kind: get_str(item, "kind")?.to_owned(),
                name: get_str(item, "name")?.to_owned(),
                full_name: get_str(item, "full_name")?.to_owned(),
                containing_class: get_str(item, "containing_class")?.to_owned(),
                top_class: get_str(item, "top_class")?.to_owned(),
                direct_invokes_exhaustive,
                direct_invokes,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(JadxXrefs {
        target: get_str(object, "target")?.to_owned(),
        overload_index,
        reported_signature,
        total: get_count(object, "total")?,
        count: get_count(object, "count")?,
        items,
    })
}

/// A `tools/call` text envelope.
pub struct JadxEnvelope {
    pub text: String,
    pub failed: bool,
}

/// `parseJadxEnvelope(response, operation)`.
pub fn parse_envelope(response: &Value, operation: &str) -> Result<JadxEnvelope, AnalysisError> {
    let unsupported = || {
        AnalysisError::output(
            operation,
            "JADX returned an unsupported MCP content envelope",
        )
    };
    let object = response.as_object().ok_or_else(unsupported)?;
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(unsupported)?;
    if content.len() != 1 {
        return Err(unsupported());
    }
    let entry = content[0].as_object().ok_or_else(unsupported)?;
    if entry.get("type").and_then(Value::as_str) != Some("text") {
        return Err(unsupported());
    }
    let text = entry
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(unsupported)?;
    let failed = object.get("isError").and_then(Value::as_bool) == Some(true);
    Ok(JadxEnvelope {
        text: text.to_owned(),
        failed,
    })
}

/// `parseJadxJson(text, operation)`.
pub fn parse_json(text: &str, operation: &str) -> Result<Value, AnalysisError> {
    serde_json::from_str(text)
        .map_err(|_| AnalysisError::output(operation, "JADX returned malformed JSON text"))
}

/// A recognised bridge failure payload.
#[derive(Clone, Debug)]
pub enum BridgeFailure {
    InvalidInput {
        field: String,
        message: String,
    },
    JvmMemory {
        memory_area: String,
        message: Option<String>,
        max_heap_bytes: u64,
    },
}

/// `parseJadxFailure(text)`: a named bridge contract, if the text matches.
pub fn parse_failure(text: &str) -> Option<BridgeFailure> {
    let value: Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    match object.get("kind").and_then(Value::as_str)? {
        "invalid-input" => {
            let field = object.get("field").and_then(Value::as_str)?;
            if !matches!(field, "class_name" | "method_name" | "overload_index") {
                return None;
            }
            let message = object.get("message").and_then(Value::as_str)?;
            if message.is_empty() {
                return None;
            }
            if object.len() != 3 {
                return None;
            }
            Some(BridgeFailure::InvalidInput {
                field: field.to_owned(),
                message: message.to_owned(),
            })
        }
        "jvm-memory-failure" => {
            let memory_area = object.get("memory_area").and_then(Value::as_str)?;
            if !matches!(memory_area, "heap" | "unknown") {
                return None;
            }
            if object.get("exception_type").and_then(Value::as_str)
                != Some("java.lang.OutOfMemoryError")
            {
                return None;
            }
            let message = match object.get("message") {
                None => None,
                Some(Value::String(text)) => Some(text.clone()),
                Some(_) => return None,
            };
            let max_heap_bytes = object
                .get("max_heap_bytes")
                .and_then(Value::as_u64)
                .filter(|value| *value > 0 && *value <= MAX_SAFE_INTEGER)?;
            let allowed = 4 + usize::from(message.is_some());
            if object.len() != allowed {
                return None;
            }
            Some(BridgeFailure::JvmMemory {
                memory_area: memory_area.to_owned(),
                message,
                max_heap_bytes,
            })
        }
        _ => None,
    }
}

/// `normalizeJadxText(text)`.
pub struct TextCoverage {
    pub status: &'static str,
    pub text: String,
    pub reported_total_bytes: Option<u64>,
}

pub fn normalize_text(text: &str) -> TextCoverage {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let regex = CELL.get_or_init(|| {
        Regex::new(r"\n\n\.\.\. \[truncated: exceeds (\d+) bytes, total (\d+) bytes\]$")
            .expect("valid truncation marker regex")
    });
    let captures = regex.captures(text);
    let total = captures
        .as_ref()
        .and_then(|captures| captures.get(2))
        .and_then(|value| value.as_str().parse::<u64>().ok())
        .filter(|value| *value <= MAX_SAFE_INTEGER);
    TextCoverage {
        status: if captures.is_some() {
            "partial"
        } else {
            "complete"
        },
        text: text.to_owned(),
        reported_total_bytes: total,
    }
}

impl TextCoverage {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "status": self.status,
            "text": self.text,
            "reported_total_bytes": self.reported_total_bytes,
        })
    }
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
