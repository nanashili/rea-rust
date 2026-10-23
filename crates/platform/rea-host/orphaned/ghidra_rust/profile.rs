//! Analysis-profile projection for the optional Rust Ghidra worker.
//!
//! Profile commitments are provider facts.  This module keeps their shape
//! independent from application-layer analysis types while retaining the
//! caller-selected worker and target values used to produce a commitment.

use crate::{
    ghidra_rust::configuration::GhidraRustConfiguration,
    ghidra_rust::memory_policy::ghidra_rust_memory_policy,
    ghidra_rust::protocol::WorkerInfo,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const GHIDRA_RUST_PROVIDER_ID: &str = "ghidra-rust";
pub const GHIDRA_RUST_PROVIDER_NAME: &str = "Ghidra Rust";
pub const GHIDRA_RUST_PROVIDER_VERSION: &str = "worker-protocol-2";
pub const WORKER_ARGUMENT: &str = "--rea-rust-ghidra-worker";

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Target facts needed by the profile without importing application domain
/// types or reconstructing target metadata at this provider boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustProfileTarget {
    pub format: String,
    pub architecture: Option<String>,
}

impl GhidraRustProfileTarget {
    pub fn executable(format: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self {
            format: format.into(),
            architecture: Some(architecture.into()),
        }
    }

    pub fn non_executable(format: impl Into<String>) -> Self {
        Self {
            format: format.into(),
            architecture: None,
        }
    }
}

/// Hash and byte count of the exact worker executable selected by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustWorkerFingerprint {
    pub sha256: String,
    pub bytes: u64,
}

/// Build the provider commitment represented by the TypeScript adapter.
pub fn profile_for(
    configuration: &GhidraRustConfiguration,
    target: &GhidraRustProfileTarget,
    fingerprint: &GhidraRustWorkerFingerprint,
) -> Value {
    let unsigned = json!({
        "provider": {
            "id": GHIDRA_RUST_PROVIDER_ID,
            "name": GHIDRA_RUST_PROVIDER_NAME,
            "version": GHIDRA_RUST_PROVIDER_VERSION,
        },
        "parameters": profile_parameters(configuration, target, fingerprint),
    });

    let digest = sha256_canonical_json(&unsigned);
    json!({
        "provider": unsigned["provider"].clone(),
        "parameters": unsigned["parameters"].clone(),
        "digest": digest,
    })
}

/// Refuse malformed, stale, or differently configured profile commitments.
pub fn profile_matches(
    profile: Option<&Value>,
    configuration: &GhidraRustConfiguration,
    target: &GhidraRustProfileTarget,
) -> bool {
    let Some(profile) = profile else {
        return false;
    };
    let Some(parameters) = profile.get("parameters").and_then(Value::as_object) else {
        return false;
    };
    let Some(sha256) = parameters.get("worker_sha256").and_then(Value::as_str) else {
        return false;
    };
    let Some(bytes) = parameters.get("worker_bytes").and_then(Value::as_u64) else {
        return false;
    };
    if !valid_digest(sha256) || bytes == 0 || bytes > MAX_SAFE_INTEGER {
        return false;
    }

    let expected = profile_for(
        configuration,
        target,
        &GhidraRustWorkerFingerprint {
            sha256: sha256.to_owned(),
            bytes,
        },
    );
    profile == &expected
}

/// Match the engine contract and the worker's canonical JSON cache identity.
pub fn worker_configuration_agrees(info: &WorkerInfo) -> bool {
    let expected_engine = ghidra_rust_engine();
    if canonical_json(&info.engine) != canonical_json(&expected_engine) {
        return false;
    }

    let encoded = canonical_json(&json!({
        "engine": info.engine,
        "worker_sha256": info.worker_sha256,
    }));
    sha256_bytes(encoded.as_bytes()) == info.config_identity
}

fn profile_parameters(
    configuration: &GhidraRustConfiguration,
    target: &GhidraRustProfileTarget,
    fingerprint: &GhidraRustWorkerFingerprint,
) -> Value {
    let mut parameters = ghidra_rust_memory_policy(configuration.memory_mib);
    let object = parameters
        .as_object_mut()
        .expect("memory policy is always a JSON object");

    object.insert("adapter_protocol_version".into(), json!(1));
    object.insert("engine".into(), ghidra_rust_engine());
    object.insert("worker_sha256".into(), json!(fingerprint.sha256));
    object.insert("worker_bytes".into(), json!(fingerprint.bytes));
    object.insert(
        "worker_command".into(),
        json!(path_display(&configuration.command)),
    );
    object.insert("worker_argument".into(), json!(WORKER_ARGUMENT));
    object.insert(
        "cache_directory".into(),
        json!(path_display(&configuration.cache_directory)),
    );
    object.insert(
        "timeout_ms".into(),
        json!(configuration.timeout.as_millis() as u64),
    );
    object.insert("snapshot_replay".into(), json!(false));
    object.insert("target_format".into(), json!(target.format));
    object.insert(
        "target_architecture".into(),
        target.architecture.clone().map_or(Value::Null, Value::String),
    );
    Value::Object(std::mem::take(object))
}

fn ghidra_rust_engine() -> Value {
    json!({
        "provider": GHIDRA_RUST_PROVIDER_ID,
        "engine_version": "2.1.0",
        "engine_revision": "268c3a406d8d964bc00ae2ead4d3e1e1373aaa27",
        "cache_id": "ghidra-rust-268c3a4-v9",
        "snapshot_schema": 1,
        "worker_protocol_version": 2,
        "worker_protocol_name": "rea-ghidra-rust-jsonrpc-lines",
        "inventory_policy": "saved-or-loader-v1",
        "analysis_policy": {
            "strings": "file-backed-data-sections-nul-terminated-utf8-v1",
            "references": "linear-pcode-constant-propagation-v1",
        },
        "program_lifecycle": {
            "max_decompile_attempts": 512,
            "idle_release_seconds": 30,
        },
        "universal_policy": "reject",
        "formats": ["Elf", "Pe", "MachO"],
        "architectures": ["I386", "X86_64", "Arm", "Aarch64"],
        "limits": {
            "request_bytes": 64 * 1024,
            "frame_bytes": 8 * 1024 * 1024,
            "batch_bytes": 6 * 1024 * 1024,
            "pseudocode_bytes": 512 * 1024,
            "function_name_bytes": 4096,
            "selector_bytes": 4096,
            "address_bytes": 18,
            "batch_size": 1024,
            "resolution_selectors": 64,
            "function_page": 256,
            "function_alias_page": 256,
            "inventory_functions": 1_000_000,
            "inventory_name_bytes": 32 * 1024 * 1024,
            "target_bytes": 256 * 1024 * 1024,
            "database_cache_bytes": 4 * 1024 * 1024,
            "instructions_per_function": 65_536,
            "string_page": 1024,
            "string_min_characters": 4,
            "string_bytes": 64 * 1024,
            "reference_page": 4096,
            "instruction_page": 4096,
            "read_bytes": 1024 * 1024,
        },
    })
}

fn path_display(path: &Path) -> String {
    path.display().to_string()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("profile JSON values are serializable")
}

fn sha256_canonical_json(value: &Value) -> String {
    sha256_bytes(canonical_json(value).as_bytes())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
