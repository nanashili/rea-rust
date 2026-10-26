//! Worker wire protocol: pinned engine contract, limits and strict reply
//! schemas.
//!
//! Compatibility owner: `src/ghidra-rust/GhidraRustProtocol.ts`. Every
//! schema is strict (unknown keys are rejected) exactly like the original
//! `z.strictObject` declarations.
use serde_json::{Map, Value, json};

pub(crate) const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub(crate) const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_BATCH_BYTES: usize = 6 * 1024 * 1024;
pub(crate) const MAX_BATCH_SIZE: usize = 1024;
pub(crate) const MAX_RESOLUTION_SELECTORS: usize = 64;
pub(crate) const MAX_PSEUDOCODE_BYTES: usize = 512 * 1024;
pub(crate) const WORKER_ARGUMENT: &str = "--rea-rust-ghidra-worker";
pub(crate) const WORKER_PROTOCOL_NAME: &str = "rea-ghidra-rust-jsonrpc-lines";
pub(crate) const WORKER_PROTOCOL_VERSION: u64 = 2;
const CACHE_ID: &str = "ghidra-rust-268c3a4-v14";
const MAX_SEARCH_PATTERN: usize = 4096;
const MAX_SEARCH_RESULTS: usize = 1000;
/// Worker inventory limits pinned by `engine().limits`; the worker enforces
/// them while freezing and the host validates them while paging.
pub(crate) const MAX_FUNCTION_PAGE: u64 = 256;
pub(crate) const MAX_ALIAS_PAGE: u64 = 256;
pub(crate) const MAX_FUNCTION_NAME_BYTES: usize = 4096;
pub(crate) const MAX_INVENTORY_FUNCTIONS: u64 = 1_000_000;
pub(crate) const MAX_INVENTORY_NAME_BYTES: usize = 32 * 1024 * 1024;
const MAX_COUNT: u64 = MAX_INVENTORY_FUNCTIONS;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// `GHIDRA_RUST_ENGINE`: engine metadata pinned independently of the
/// external executable hash.
pub(crate) fn engine() -> Value {
    json!({
        "provider": "ghidra-rust",
        "engine_version": "2.1.0",
        "engine_revision": "268c3a406d8d964bc00ae2ead4d3e1e1373aaa27",
        "cache_id": CACHE_ID,
        "snapshot_schema": 1,
        "worker_protocol_version": WORKER_PROTOCOL_VERSION,
        "worker_protocol_name": WORKER_PROTOCOL_NAME,
        "host_architecture": std::env::consts::ARCH,
        "inventory_policy": "saved-or-loader-v1",
        "analysis_policy": {
            "strings": "file-backed-data-sections-nul-terminated-utf8-v1",
            "references": "linear-pcode-constant-propagation-v1",
            "image_map": "verified-file-backed-ranges-v1",
            "search_bytes": "masked-file-backed-ranges-v1",
            "inspect_instruction": "decoder-pcode-observation-v1",
        },
        "program_lifecycle": {
            "max_decompile_attempts": 512,
            "idle_release_seconds": 30,
        },
        "universal_policy": "select-host-architecture",
        "formats": ["Elf", "Pe", "MachO"],
        "architectures": ["I386", "X86_64", "Arm", "Aarch64"],
        "limits": {
            "request_bytes": MAX_REQUEST_BYTES,
            "frame_bytes": MAX_FRAME_BYTES,
            "batch_bytes": MAX_BATCH_BYTES,
            "pseudocode_bytes": MAX_PSEUDOCODE_BYTES,
            "function_name_bytes": MAX_FUNCTION_NAME_BYTES,
            "selector_bytes": 4096,
            "address_bytes": 18,
            "batch_size": MAX_BATCH_SIZE,
            "resolution_selectors": MAX_RESOLUTION_SELECTORS,
            "function_page": MAX_FUNCTION_PAGE,
            "function_alias_page": MAX_ALIAS_PAGE,
            "inventory_functions": MAX_INVENTORY_FUNCTIONS,
            "inventory_name_bytes": MAX_INVENTORY_NAME_BYTES,
            "target_bytes": 256 * 1024 * 1024,
            "database_cache_bytes": 4 * 1024 * 1024,
            "instructions_per_function": 65_536,
            "string_page": crate::analysis::MAX_STRING_PAGE,
            "string_min_characters": 4,
            "string_bytes": 64 * 1024,
            "reference_page": crate::analysis::MAX_REFERENCE_PAGE,
            "instruction_page": crate::analysis::MAX_INSTRUCTION_PAGE,
            "read_bytes": crate::analysis::MAX_READ_BYTES,
            "search_pattern": MAX_SEARCH_PATTERN,
            "search_results": MAX_SEARCH_RESULTS,
            "image_map_ranges": 4096,
        },
    })
}

type Check<T> = Result<T, String>;

fn strict<'a>(value: &'a Value, allowed: &[&str], context: &str) -> Check<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{context}: expected object"))?;
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("{context}: unrecognized key \"{unknown}\""));
    }
    Ok(object)
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Check<&'a Value> {
    object.get(key).ok_or_else(|| format!("{key}: required"))
}

/// `bytes(maximum)`: a string whose UTF-8 encoding fits `maximum` bytes.
fn text(value: &Value, maximum: usize, key: &str) -> Check<String> {
    match value.as_str() {
        Some(text) if text.len() <= maximum => Ok(text.to_owned()),
        Some(_) => Err(format!("{key}: exceeds {maximum} bytes")),
        None => Err(format!("{key}: expected string")),
    }
}

fn nullable_text(value: &Value, maximum: usize, key: &str) -> Check<Option<String>> {
    if value.is_null() {
        Ok(None)
    } else {
        text(value, maximum, key).map(Some)
    }
}

fn optional<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key)
}

/// A JSON number that is an integer within `0..=maximum`.
fn integer(value: &Value, minimum: u64, maximum: u64, key: &str) -> Check<u64> {
    let parsed = if let Some(integer) = value.as_u64() {
        Some(integer)
    } else {
        value
            .as_f64()
            .filter(|number| {
                number.fract() == 0.0 && *number >= 0.0 && *number <= MAX_SAFE_INTEGER as f64
            })
            .map(|number| number as u64)
    };
    match parsed {
        Some(integer) if integer >= minimum && integer <= maximum => Ok(integer),
        _ => Err(format!("{key}: expected integer in {minimum}..={maximum}")),
    }
}

fn count(value: &Value, key: &str) -> Check<u64> {
    integer(value, 0, MAX_COUNT, key)
}

fn boolean(value: &Value, key: &str) -> Check<bool> {
    value
        .as_bool()
        .ok_or_else(|| format!("{key}: expected boolean"))
}

fn literal(value: &Value, expected: &Value, key: &str) -> Check<()> {
    if value == expected {
        Ok(())
    } else {
        Err(format!("{key}: expected {expected}"))
    }
}

/// `workerDigestSchema`: `^[a-f0-9]{64}$`.
pub(crate) fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn digest(value: &Value, key: &str) -> Check<String> {
    match value.as_str() {
        Some(text) if is_digest(text) => Ok(text.to_owned()),
        _ => Err(format!("{key}: expected lowercase SHA-256 digest")),
    }
}

/// `workerAddressSchema`: `^0x(?:0|[1-9a-f][a-f0-9]{0,15})$`.
pub(crate) fn is_address(text: &str) -> bool {
    let Some(digits) = text.strip_prefix("0x") else {
        return false;
    };
    let hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    match digits.as_bytes() {
        [b'0'] => true,
        [first, rest @ ..] => {
            *first != b'0' && hex(*first) && rest.len() <= 15 && rest.iter().all(|byte| hex(*byte))
        }
        [] => false,
    }
}

fn address(value: &Value, key: &str) -> Check<String> {
    match value.as_str() {
        Some(text) if is_address(text) => Ok(text.to_owned()),
        _ => Err(format!("{key}: expected canonical address")),
    }
}

fn nullable_address(value: &Value, key: &str) -> Check<Option<String>> {
    if value.is_null() {
        Ok(None)
    } else {
        address(value, key).map(Some)
    }
}

fn array<'a>(value: &'a Value, maximum: usize, key: &str) -> Check<&'a Vec<Value>> {
    match value.as_array() {
        Some(items) if items.len() <= maximum => Ok(items),
        Some(_) => Err(format!("{key}: more than {maximum} items")),
        None => Err(format!("{key}: expected array")),
    }
}

/// Parsed `workerInfoSchema`, retaining the exact reply value.
#[derive(Clone, Debug)]
pub(crate) struct WorkerInfo {
    pub raw: Value,
    pub engine: Value,
    pub worker_sha256: String,
    pub config_identity: String,
    pub inventory_frozen: bool,
    pub timeout_ms: u64,
    pub capabilities: Vec<String>,
    pub target_sha256: Option<String>,
    pub inventory_sha256: Option<String>,
    pub indexed_functions: Option<u64>,
    pub total: Option<u64>,
    pub preparation: Option<String>,
    pub limitations: Vec<String>,
}

const INFO_KEYS: [&str; 19] = [
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
];

/// `workerInfoSchema.safeParse`.
pub(crate) fn parse_info(value: &Value) -> Check<WorkerInfo> {
    let object = strict(value, &INFO_KEYS, "worker info")?;
    let engine = required(object, "engine")?;
    if !engine.is_object() {
        return Err("engine: expected object".into());
    }
    literal(
        required(object, "provider")?,
        &json!("ghidra-rust"),
        "provider",
    )?;
    let version = required(object, "worker_protocol_version")?;
    if version.as_f64() != Some(WORKER_PROTOCOL_VERSION as f64) {
        return Err("worker_protocol_version: unexpected version".into());
    }
    literal(
        required(object, "worker_protocol_name")?,
        &json!(WORKER_PROTOCOL_NAME),
        "worker_protocol_name",
    )?;
    literal(required(object, "cache_id")?, &json!(CACHE_ID), "cache_id")?;
    if required(object, "snapshot_schema")?.as_f64() != Some(1.0) {
        return Err("snapshot_schema: expected 1".into());
    }
    let worker_sha256 = digest(required(object, "worker_sha256")?, "worker_sha256")?;
    let config_identity = digest(required(object, "config_identity")?, "config_identity")?;
    let inventory_frozen = boolean(required(object, "inventory_frozen")?, "inventory_frozen")?;
    if !required(object, "memory_limit_mib")?.is_null() {
        return Err("memory_limit_mib: expected null".into());
    }
    let timeout_ms = integer(
        required(object, "timeout_ms")?,
        1,
        MAX_SAFE_INTEGER,
        "timeout_ms",
    )?;
    let capabilities = array(required(object, "capabilities")?, 32, "capabilities")?
        .iter()
        .map(|capability| text(capability, 64, "capabilities"))
        .collect::<Check<Vec<_>>>()?;
    let target_sha256 = optional(object, "target_sha256")
        .map(|value| digest(value, "target_sha256"))
        .transpose()?;
    let inventory_sha256 = optional(object, "inventory_sha256")
        .map(|value| digest(value, "inventory_sha256"))
        .transpose()?;
    let indexed_functions = optional(object, "indexed_functions")
        .map(|value| count(value, "indexed_functions"))
        .transpose()?;
    let total = optional(object, "total")
        .map(|value| count(value, "total"))
        .transpose()?;
    let preparation = match optional(object, "preparation") {
        None => None,
        Some(value) => match value.as_str() {
            Some(text @ ("restored" | "loader_inventory")) => Some(text.to_owned()),
            _ => return Err("preparation: unexpected value".into()),
        },
    };
    if let Some(language) = optional(object, "language") {
        text(language, 4096, "language")?;
    }
    let limitations = match optional(object, "limitations") {
        None => Vec::new(),
        Some(value) => array(value, 32, "limitations")?
            .iter()
            .map(|limitation| text(limitation, 4096, "limitations"))
            .collect::<Check<Vec<_>>>()?,
    };
    Ok(WorkerInfo {
        raw: value.clone(),
        engine: engine.clone(),
        worker_sha256,
        config_identity,
        inventory_frozen,
        timeout_ms,
        capabilities,
        target_sha256,
        inventory_sha256,
        indexed_functions,
        total,
        preparation,
        limitations,
    })
}

/// One saved-inventory procedure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Procedure {
    pub address: String,
    pub name: String,
}

/// Parsed `functionPageSchema`.
pub(crate) struct FunctionPage {
    pub items: Vec<Procedure>,
    pub offset: u64,
    pub next_offset: Option<u64>,
    pub indexed_functions: u64,
    pub total: u64,
    pub inventory_sha256: String,
}

pub(crate) fn parse_function_page(value: &Value) -> Check<FunctionPage> {
    let object = strict(
        value,
        &[
            "items",
            "offset",
            "next_offset",
            "indexed_functions",
            "total",
            "inventory_sha256",
        ],
        "function page",
    )?;
    let items = array(
        required(object, "items")?,
        MAX_FUNCTION_PAGE as usize,
        "items",
    )?
    .iter()
    .map(|item| {
        let item = strict(item, &["address", "name"], "function")?;
        Ok(Procedure {
            address: address(required(item, "address")?, "address")?,
            name: text(required(item, "name")?, MAX_FUNCTION_NAME_BYTES, "name")?,
        })
    })
    .collect::<Check<Vec<_>>>()?;
    let next = required(object, "next_offset")?;
    Ok(FunctionPage {
        items,
        offset: count(required(object, "offset")?, "offset")?,
        next_offset: if next.is_null() {
            None
        } else {
            Some(count(next, "next_offset")?)
        },
        indexed_functions: count(required(object, "indexed_functions")?, "indexed_functions")?,
        total: count(required(object, "total")?, "total")?,
        inventory_sha256: digest(required(object, "inventory_sha256")?, "inventory_sha256")?,
    })
}

/// Parsed `function_aliases` page: additional loader names at entries.
pub(crate) struct AliasPage {
    pub items: Vec<Procedure>,
    pub offset: u64,
    pub next_offset: Option<u64>,
    pub total: u64,
    pub aliases_sha256: String,
    pub inventory_sha256: String,
}

pub(crate) fn parse_alias_page(value: &Value) -> Check<AliasPage> {
    let object = strict(
        value,
        &[
            "items",
            "offset",
            "next_offset",
            "total",
            "aliases_sha256",
            "inventory_sha256",
        ],
        "alias page",
    )?;
    let items = array(required(object, "items")?, MAX_ALIAS_PAGE as usize, "items")?
        .iter()
        .map(|item| {
            let item = strict(item, &["address", "name"], "alias")?;
            let name = text(required(item, "name")?, MAX_FUNCTION_NAME_BYTES, "name")?;
            if name.is_empty() {
                return Err("name: expected a nonempty alias".into());
            }
            Ok(Procedure {
                address: address(required(item, "address")?, "address")?,
                name,
            })
        })
        .collect::<Check<Vec<_>>>()?;
    let next = required(object, "next_offset")?;
    Ok(AliasPage {
        items,
        offset: count(required(object, "offset")?, "offset")?,
        next_offset: if next.is_null() {
            None
        } else {
            Some(count(next, "next_offset")?)
        },
        total: count(required(object, "total")?, "total")?,
        aliases_sha256: digest(required(object, "aliases_sha256")?, "aliases_sha256")?,
        inventory_sha256: digest(required(object, "inventory_sha256")?, "inventory_sha256")?,
    })
}

/// Selector-resolution status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionStatus {
    Found,
    NotFound,
    Ambiguous,
}

/// One `functionResolutionSchema` item.
#[derive(Clone, Debug)]
pub(crate) struct Resolution {
    pub selector: String,
    pub status: ResolutionStatus,
    pub address: Option<String>,
    pub name: Option<String>,
}

pub(crate) struct ResolutionPage {
    pub items: Vec<Resolution>,
    pub inventory_sha256: String,
}

pub(crate) fn parse_resolution(value: &Value) -> Check<ResolutionPage> {
    let object = strict(value, &["items", "inventory_sha256"], "resolution page")?;
    let items = array(
        required(object, "items")?,
        MAX_RESOLUTION_SELECTORS,
        "items",
    )?
    .iter()
    .map(|item| {
        let item = strict(
            item,
            &["selector", "status", "address", "name"],
            "resolution",
        )?;
        let status = match required(item, "status")?.as_str() {
            Some("found") => ResolutionStatus::Found,
            Some("not_found") => ResolutionStatus::NotFound,
            Some("ambiguous") => ResolutionStatus::Ambiguous,
            _ => return Err("status: unexpected value".into()),
        };
        Ok(Resolution {
            selector: text(required(item, "selector")?, 4096, "selector")?,
            status,
            address: nullable_address(required(item, "address")?, "address")?,
            name: nullable_text(required(item, "name")?, 4096, "name")?,
        })
    })
    .collect::<Check<Vec<_>>>()?;
    Ok(ResolutionPage {
        items,
        inventory_sha256: digest(required(object, "inventory_sha256")?, "inventory_sha256")?,
    })
}

/// One object-file section.
pub(crate) struct Segment {
    pub name: String,
    pub address: String,
    pub end: String,
}

/// Parsed `segmentPageSchema`.
pub(crate) struct SegmentPage {
    pub items: Vec<Segment>,
}

pub(crate) fn parse_segments(value: &Value) -> Check<SegmentPage> {
    let object = strict(value, &["items", "coverage"], "segment page")?;
    let items = array(required(object, "items")?, 4096, "items")?
        .iter()
        .map(|item| {
            let item = strict(item, &["name", "address", "end", "executable"], "segment")?;
            boolean(required(item, "executable")?, "executable")?;
            Ok(Segment {
                name: text(required(item, "name")?, 4096, "name")?,
                address: address(required(item, "address")?, "address")?,
                end: address(required(item, "end")?, "end")?,
            })
        })
        .collect::<Check<Vec<_>>>()?;
    text(required(object, "coverage")?, 4096, "coverage")?;
    Ok(SegmentPage { items })
}

/// One `workerBatchItemSchema` item, retaining its exact reply value.
#[derive(Clone, Debug)]
pub(crate) struct BatchItem {
    pub raw: Value,
    pub selector: String,
    pub address: Option<String>,
    pub name: Option<String>,
    pub pseudocode: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

/// `workerBatchDurabilitySchema`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Durability {
    pub confirmed_addresses: Vec<String>,
    pub unconfirmed_addresses: Vec<String>,
}

/// `workerBatchFailureSchema`.
#[derive(Clone, Debug)]
pub(crate) struct BatchFailure {
    pub error_message: String,
    pub cause_code: String,
}

/// Parsed `batchReplySchema`.
#[derive(Clone, Debug)]
pub(crate) struct BatchReply {
    pub items: Vec<BatchItem>,
    pub total: u64,
    pub completed: u64,
    pub inventory_sha256: String,
    pub durability: Durability,
    pub failure: Option<BatchFailure>,
}

fn parse_durability(value: &Value) -> Check<Durability> {
    let object = strict(
        value,
        &["confirmed_addresses", "unconfirmed_addresses"],
        "durability",
    )?;
    let list = |key: &str| -> Check<Vec<String>> {
        array(required(object, key)?, MAX_BATCH_SIZE, key)?
            .iter()
            .map(|item| address(item, key))
            .collect()
    };
    Ok(Durability {
        confirmed_addresses: list("confirmed_addresses")?,
        unconfirmed_addresses: list("unconfirmed_addresses")?,
    })
}

/// `workerBatchFailureSchema.safeParse`.
pub(crate) fn parse_batch_failure(value: &Value) -> Check<BatchFailure> {
    let object = strict(
        value,
        &["error_code", "error_message", "cause_code"],
        "failure",
    )?;
    literal(
        required(object, "error_code")?,
        &json!("BATCH_INTERRUPTED"),
        "error_code",
    )?;
    let cause_code = match required(object, "cause_code")?.as_str() {
        Some(code @ ("WORKER_FAILED" | "CACHE_INTEGRITY_FAILED")) => code.to_owned(),
        _ => return Err("cause_code: unexpected value".into()),
    };
    Ok(BatchFailure {
        error_message: text(required(object, "error_message")?, 4096, "error_message")?,
        cause_code,
    })
}

pub(crate) fn parse_batch_reply(value: &Value) -> Check<BatchReply> {
    let object = strict(
        value,
        &[
            "items",
            "total",
            "completed",
            "inventory_sha256",
            "durability",
            "failure",
        ],
        "batch reply",
    )?;
    let items = array(required(object, "items")?, MAX_BATCH_SIZE, "items")?
        .iter()
        .map(|item| {
            let fields = strict(
                item,
                &[
                    "selector",
                    "address",
                    "name",
                    "pseudocode",
                    "error_code",
                    "error_message",
                ],
                "batch item",
            )?;
            Ok(BatchItem {
                raw: item.clone(),
                selector: text(required(fields, "selector")?, 18, "selector")?,
                address: nullable_address(required(fields, "address")?, "address")?,
                name: nullable_text(required(fields, "name")?, 4096, "name")?,
                pseudocode: nullable_text(
                    required(fields, "pseudocode")?,
                    MAX_PSEUDOCODE_BYTES,
                    "pseudocode",
                )?,
                error_code: nullable_text(required(fields, "error_code")?, 64, "error_code")?,
                error_message: nullable_text(
                    required(fields, "error_message")?,
                    4096,
                    "error_message",
                )?,
            })
        })
        .collect::<Check<Vec<_>>>()?;
    let failure = optional(object, "failure")
        .map(parse_batch_failure)
        .transpose()?;
    Ok(BatchReply {
        items,
        total: integer(
            required(object, "total")?,
            0,
            MAX_BATCH_SIZE as u64,
            "total",
        )?,
        completed: integer(
            required(object, "completed")?,
            0,
            MAX_BATCH_SIZE as u64,
            "completed",
        )?,
        inventory_sha256: digest(required(object, "inventory_sha256")?, "inventory_sha256")?,
        durability: parse_durability(required(object, "durability")?)?,
        failure,
    })
}

/// One `rpcFrameSchema` frame.
pub(crate) enum Frame {
    Reply {
        id: u64,
        result: Value,
    },
    Error {
        id: u64,
        message: String,
        error_code: String,
    },
    Progress {
        label: String,
        completed: u64,
        total: Option<u64>,
    },
}

pub(crate) fn parse_frame(value: &Value) -> Check<Frame> {
    let object = value.as_object().ok_or("worker frame: expected object")?;
    literal(required(object, "jsonrpc")?, &json!("2.0"), "jsonrpc")?;
    if object.contains_key("method") {
        strict(value, &["jsonrpc", "method", "params"], "progress frame")?;
        literal(
            required(object, "method")?,
            &json!("analysis/progress"),
            "method",
        )?;
        let params = strict(
            required(object, "params")?,
            &["label", "completed", "total"],
            "params",
        )?;
        let total = required(params, "total")?;
        return Ok(Frame::Progress {
            label: text(required(params, "label")?, 4096, "label")?,
            completed: integer(
                required(params, "completed")?,
                0,
                MAX_SAFE_INTEGER,
                "completed",
            )?,
            total: if total.is_null() {
                None
            } else {
                Some(integer(total, 0, MAX_SAFE_INTEGER, "total")?)
            },
        });
    }
    let id = integer(required(object, "id")?, 1, MAX_SAFE_INTEGER, "id")?;
    if object.contains_key("result") {
        strict(value, &["jsonrpc", "id", "result"], "reply frame")?;
        return Ok(Frame::Reply {
            id,
            result: object["result"].clone(),
        });
    }
    strict(value, &["jsonrpc", "id", "error"], "error frame")?;
    let error = strict(
        required(object, "error")?,
        &["code", "message", "data"],
        "error",
    )?;
    if required(error, "code")?.as_f64() != Some(-32000.0) {
        return Err("error.code: expected -32000".into());
    }
    let data = strict(required(error, "data")?, &["error_code"], "error.data")?;
    let error_code = match required(data, "error_code")?.as_str() {
        Some(code @ ("WORKER_FAILED" | "CACHE_INTEGRITY_FAILED")) => code.to_owned(),
        _ => return Err("error.data.error_code: unexpected value".into()),
    };
    Ok(Frame::Error {
        id,
        message: text(required(error, "message")?, 4096, "error.message")?,
        error_code,
    })
}
