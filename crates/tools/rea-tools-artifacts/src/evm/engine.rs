//! In-process EVMole 0.9.3 interface recovery (the owned-worker computation).
//!
//! Compatibility owners:
//! - `src/evm/EvmoleInterfaceWorker.ts` (`main`): carrier decoding, EF00
//!   guard, the `engine.contractInfo(hex, { selectors, arguments,
//!   stateMutability })` call, SHA-256, the Solidity CBOR metadata candidate,
//!   and the reply shape.
//! - `src/evm/EvmoleInterfaceAdapter.ts` (`projectEvmoleInterface`,
//!   `evmoleInterfaceReplySchema`): the producer representation and the
//!   portable `functions` projection.
//! - `~/.cargo/.../evmole-0.9.3/src/interface_js.rs` + `contract_info.rs` +
//!   `serialize.rs`: the exact `contractInfo` option mapping and the
//!   `selector`/`arguments`/`stateMutability`/`dispatch` JSON encodings.
//!
//! The TypeScript provider runs this computation inside an owned Node child
//! under util-linux `prlimit`. The native binary has no worker entrypoint this
//! crate may launch, so the same engine release runs in-process. The isolation
//! guarantees that are therefore NOT reproduced are documented in the caller
//! (`super::inspect`), its `limitations`, and the worker report. Every byte,
//! size, selector and representation budget that bounds input and output is
//! preserved.

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::carrier::{self, CarrierFailure, Encoding};
use super::metadata;

/// The `ok: true` reply the provider validates (`replySchema`), already
/// projected to portable `functions` and bound to decoded byte identity.
pub(crate) struct EngineReply {
    /// SHA-256 of the decoded bytecode (lowercase hex).
    pub sha256: String,
    /// Decoded bytecode length in bytes.
    pub bytes: usize,
    /// Decoded bytecode as lowercase hex.
    pub hex: String,
    /// `bytecode.metadata`: the independent terminal CBOR candidate.
    pub metadata: Value,
    /// `raw`: the exact producer representation (`evmoleInterfaceReplySchema`).
    pub raw: Value,
    /// Portable interface candidates (`projectEvmoleInterface(...).functions`).
    pub functions: Vec<Value>,
}

/// Expected, reply-mapped engine failures (`reply.reason`), mirroring the
/// worker's `ok: false` branch kinds.
pub(crate) enum EngineFailure {
    /// `reason: "format"` — a carrier encoding failure (`EvmCarrierFailure`).
    Format(&'static str),
    /// `reason: "unsupported"` — an EOF-style `EF00` container.
    Unsupported(&'static str),
}

/// Port of `EvmoleInterfaceWorker.main`: decode the carrier, guard `EF00`,
/// recover the interface with EVMole, and assemble the reply.
pub(crate) fn run(carrier_bytes: &[u8], encoding: Encoding) -> Result<EngineReply, EngineFailure> {
    let decoded = decode_carrier(carrier_bytes, encoding)?;

    // `if (bytes[0] === 0xef && bytes[1] === 0x00)` — container marker EF00.
    if decoded.first() == Some(&0xef) && decoded.get(1) == Some(&0x00) {
        return Err(EngineFailure::Unsupported(
            "Container marker EF00 is outside the verified flat-bytecode interface profile.",
        ));
    }

    // `engine.contractInfo(hex, { selectors: true, arguments: true, stateMutability: true })`.
    // In the Rust crate these options map to the equivalent builder, each of
    // which also enables `need_selectors` (see `contract_info.rs`).
    let args = evmole::ContractInfoArgs::new(&decoded)
        .with_selectors()
        .with_arguments()
        .with_state_mutability();
    let contract = evmole::contract_info(args);

    let (raw, functions) = project_interface(&contract);

    let sha256 = format!("{:x}", Sha256::new().chain_update(&decoded).finalize());
    let hex = hex_lower(&decoded);
    let metadata = metadata::inspect_solidity_metadata(&decoded);

    Ok(EngineReply {
        sha256,
        bytes: decoded.len(),
        hex,
        metadata,
        raw,
        functions,
    })
}

/// `decodeEvmBytecodeCarrier`, translating `EvmCarrierFailure` to the `format`
/// reply reason (`cause instanceof EvmCarrierFailure ? "format" : ...`).
fn decode_carrier(bytes: &[u8], encoding: Encoding) -> Result<Vec<u8>, EngineFailure> {
    carrier::decode_evm_bytecode_carrier(bytes, encoding)
        .map_err(|CarrierFailure { message }| EngineFailure::Format(message))
}

/// `projectEvmoleInterface(engine.contractInfo(...))`: build the exact
/// producer `raw` (`evmoleInterfaceReplySchema`) and the portable functions.
///
/// The producer object carries only the keys the unchanged JS binding exposes
/// as present (`functions`, and `metadata` when requested and valid); the
/// disabled facets are own `undefined` keys whose JSON transport is absence.
fn project_interface(contract: &evmole::Contract) -> (Value, Vec<Value>) {
    let producer_functions: Vec<Value> = contract
        .functions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(producer_function)
        .collect();

    let mut raw = Map::new();
    raw.insert("functions".into(), Value::Array(producer_functions.clone()));
    if let Some(cbor) = &contract.metadata {
        raw.insert("metadata".into(), metadata::reported_metadata(cbor));
    }

    let functions = producer_functions.iter().map(portable_function).collect();
    (Value::Object(raw), functions)
}

/// One producer function row (`evmoleInterfaceReplySchema.functions` item),
/// using EVMole's own serde encoding for `selector` (lowercase hex),
/// `arguments` (canonical joined type names) and `stateMutability`.
fn producer_function(function: &evmole::Function) -> Value {
    // `selectors`, `arguments` and `stateMutability` are all requested, so the
    // crate's serde `Serialize` for `Function` emits every field. Reuse it to
    // reproduce the exact JS-binding encodings, then strip the `null`s that the
    // JS binding transports as absent keys.
    let encoded = serde_json::to_value(function).unwrap_or_else(|_| Value::Object(Map::new()));
    let Value::Object(mut object) = encoded else {
        return Value::Object(Map::new());
    };

    let mut row = Map::new();
    if let Some(selector) = object.remove("selector") {
        row.insert("selector".into(), selector);
    }
    if let Some(offset) = object.remove("bytecodeOffset") {
        row.insert("bytecodeOffset".into(), offset);
    }
    if let Some(dispatch) = object.remove("dispatch") {
        row.insert("dispatch".into(), dispatch);
    }
    // `arguments` / `stateMutability` are always present here (both requested)
    // and never null, but guard defensively against a `null` transported-absent
    // key to match `z.string().optional()`.
    if let Some(arguments) = object.remove("arguments").filter(|value| !value.is_null()) {
        row.insert("arguments".into(), arguments);
    }
    if let Some(mutability) = object
        .remove("stateMutability")
        .filter(|value| !value.is_null())
    {
        row.insert("stateMutability".into(), mutability);
    }
    Value::Object(row)
}

/// Portable function projection (`projectEvmoleInterface.functions`):
/// `0x`-prefixed selector and explicit `null` for absent inference strings.
fn portable_function(producer: &Value) -> Value {
    let object = producer.as_object();
    let selector = object
        .and_then(|row| row.get("selector"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let bytecode_offset = object
        .and_then(|row| row.get("bytecodeOffset"))
        .cloned()
        .unwrap_or(Value::Null);
    let dispatch = object
        .and_then(|row| row.get("dispatch"))
        .cloned()
        .unwrap_or(Value::Null);
    let inferred_arguments = object
        .and_then(|row| row.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);
    let inferred_state_mutability = object
        .and_then(|row| row.get("stateMutability"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "selector": format!("0x{selector}"),
        "bytecode_offset": bytecode_offset,
        "dispatch": dispatch,
        "inferred_arguments": inferred_arguments,
        "inferred_state_mutability": inferred_state_mutability,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}
