//! Worker fingerprint and analysis-profile commitment.
//!
//! Compatibility owners: `src/ghidra-rust/GhidraRustProfile.ts` and
//! `GhidraRustFingerprint.ts`.
use crate::configuration::{Configuration, memory_policy};
use crate::identity::{PROVIDER_ID, identity};
use crate::protocol::{WORKER_ARGUMENT, WorkerInfo, engine, is_digest};
use rea_analysis::{BinaryTarget, create_analysis_profile};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const HASH_CHUNK_BYTES: usize = 1024 * 1024;

/// Exact worker executable identity committed by the profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Fingerprint {
    pub sha256: String,
    pub bytes: u64,
}

fn profile_error(message: impl Into<String>) -> AnalysisError {
    AnalysisError::provider_adapter(PROVIDER_ID, "profile").with_user_message(message)
}

/// Stable identity facts of one open file.
#[derive(Debug, Eq, PartialEq)]
struct FileIdentity {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        length: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    }
}

/// `fingerprintGhidraRustWorker`: hash the worker executable while proving
/// its identity did not change during the read (`hashStableFile`).
pub(crate) fn fingerprint(
    path: &str,
    cancellation: &Cancellation,
) -> Result<Fingerprint, AnalysisError> {
    let cancelled = || AnalysisError::cancelled("profile");
    if cancellation.reason().is_some() {
        return Err(cancelled());
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| profile_error(format!("Error: {error}, open '{path}'")))?;
    let before = file
        .metadata()
        .map_err(|error| profile_error(format!("Error: {error}, stat '{path}'")))?;
    if !before.is_file() {
        return Err(profile_error(format!(
            "Error: The worker is not a regular file: '{path}'"
        )));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; HASH_CHUNK_BYTES];
    let mut bytes = 0_u64;
    loop {
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        let count = match file.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(profile_error(format!("Error: {error}, read '{path}'"))),
        };
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        bytes += count as u64;
    }
    let after = file
        .metadata()
        .map_err(|error| profile_error(format!("Error: {error}, stat '{path}'")))?;
    let current = std::fs::metadata(path)
        .map_err(|error| profile_error(format!("Error: {error}, stat '{path}'")))?;
    let identity = file_identity(&before);
    if identity != file_identity(&after)
        || identity != file_identity(&current)
        || bytes != before.len()
    {
        return Err(profile_error(format!(
            "Error: The worker executable changed while it was fingerprinted: '{path}'"
        )));
    }
    if cancellation.reason().is_some() {
        return Err(cancelled());
    }
    Ok(Fingerprint {
        sha256: format!("{:x}", hash.finalize()),
        bytes,
    })
}

/// `profileFor`: commit executable, specifications, inventory policy and
/// resource controls.
pub(crate) fn profile_for(
    configuration: &Configuration,
    target: &BinaryTarget,
    fingerprint: &Fingerprint,
) -> Result<Value, AnalysisError> {
    let mut parameters = Map::new();
    parameters.insert("adapter_protocol_version".into(), json!(1));
    parameters.insert("engine".into(), engine());
    parameters.insert("worker_sha256".into(), json!(fingerprint.sha256));
    parameters.insert("worker_bytes".into(), json!(fingerprint.bytes));
    parameters.insert("worker_command".into(), json!(configuration.command));
    parameters.insert("worker_argument".into(), json!(WORKER_ARGUMENT));
    parameters.insert(
        "cache_directory".into(),
        json!(configuration.cache_directory),
    );
    parameters.insert("timeout_ms".into(), json!(configuration.timeout_ms));
    parameters.insert("memory_mib".into(), json!(configuration.memory_mib));
    for (key, value) in memory_policy(configuration.memory_mib) {
        parameters.insert(key, value);
    }
    parameters.insert("snapshot_replay".into(), json!(false));
    parameters.insert("target_format".into(), json!(target.format));
    parameters.insert(
        "target_architecture".into(),
        if target.kind == "executable" {
            json!(target.architecture)
        } else {
            Value::Null
        },
    );
    create_analysis_profile(&identity(), Value::Object(parameters))
}

/// `analysisProfileSchema` validity: provider, parameters and a digest that
/// commits to them.
fn profile_valid(profile: &Value) -> bool {
    let Some(object) = profile.as_object() else {
        return false;
    };
    let (Some(provider), Some(parameters), Some(digest)) = (
        object.get("provider").and_then(Value::as_object),
        object
            .get("parameters")
            .filter(|parameters| parameters.is_object()),
        object.get("digest").and_then(Value::as_str),
    ) else {
        return false;
    };
    if object.len() != 3
        || !provider.get("id").is_some_and(Value::is_string)
        || !provider.get("name").is_some_and(Value::is_string)
        || !provider
            .get("version")
            .is_some_and(|version| version.is_string() || version.is_null())
    {
        return false;
    }
    let unsigned = json!({ "provider": Value::Object(provider.clone()), "parameters": parameters });
    rea_core::canonical_json::digest(&unsigned).is_ok_and(|computed| computed == digest)
}

/// `analysisProfilesEqual`.
fn profiles_equal(left: &Value, right: &Value) -> bool {
    left["digest"] == right["digest"]
        && left["provider"]["id"] == right["provider"]["id"]
        && left["provider"]["name"] == right["provider"]["name"]
        && left["provider"]["version"] == right["provider"]["version"]
}

/// `ghidraRustProfileMatches`: refuse stale, foreign or differently
/// configured commitments before launch.
pub(crate) fn profile_matches(
    profile: Option<&Value>,
    configuration: &Configuration,
    target: &BinaryTarget,
) -> bool {
    let Some(profile) = profile.filter(|profile| profile_valid(profile)) else {
        return false;
    };
    let parameters = &profile["parameters"];
    let Some(sha256) = parameters["worker_sha256"]
        .as_str()
        .filter(|sha256| is_digest(sha256))
    else {
        return false;
    };
    let Some(bytes) = parameters["worker_bytes"]
        .as_u64()
        .filter(|bytes| *bytes > 0 && *bytes <= MAX_SAFE_INTEGER)
    else {
        return false;
    };
    let fingerprint = Fingerprint {
        sha256: sha256.to_owned(),
        bytes,
    };
    profile_for(configuration, target, &fingerprint)
        .is_ok_and(|expected| profiles_equal(profile, &expected))
}

/// `workerConfigurationAgrees`: match the engine contract and the worker's
/// sorted-JSON cache identity.
pub(crate) fn worker_configuration_agrees(info: &WorkerInfo) -> bool {
    let (Ok(reported), Ok(pinned)) = (
        rea_core::canonical_json::digest(&info.engine),
        rea_core::canonical_json::digest(&engine()),
    ) else {
        return false;
    };
    if reported != pinned {
        return false;
    }
    rea_core::canonical_json::digest(&json!({
        "engine": info.engine,
        "worker_sha256": info.worker_sha256,
    }))
    .is_ok_and(|identity| identity == info.config_identity)
}
