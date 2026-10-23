//! Selected-target digest verification before launch.
//!
//! Compatibility owner: `src/native/NativeCallTarget.ts`
//! (`verifyNativeCallTarget`, `nativeCallTargetFailure`) over
//! `src/filesystem/StableFileHash.ts` (`hashStableFile`). One regular
//! descriptor is opened without following a final symlink, hashed in
//! chunks, and its identity is revalidated against the path after reading;
//! a changed file is an integrity failure, not a digest mismatch.

use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::MetadataExt;

const OPERATION: &str = "observe_native_calls";
const PROVIDER: &str = "native-macos";

/// Identity facts that must stay equal across the digest.
fn fingerprint(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

fn adapter_failure(path: &str, detail: String) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("path".into(), json!(path));
    diagnostics.insert("phase".into(), json!("target-digest"));
    diagnostics.insert(
        "reason".into(),
        json!("Unable to verify the selected target digest"),
    );
    diagnostics.insert("detail".into(), json!(detail));
    AnalysisError::provider_adapter(PROVIDER, OPERATION).with_diagnostics(diagnostics)
}

fn changed() -> AnalysisError {
    AnalysisError::evidence_integrity(
        "Native call observation target changed during digest verification",
    )
}

/// `verifyNativeCallTarget`: the selected path still hashes to the bound digest.
pub(crate) fn verify(
    path: &str,
    sha256: &str,
    cancellation: &Cancellation,
) -> Result<(), AnalysisError> {
    use std::os::unix::fs::OpenOptionsExt;
    let io = |error: std::io::Error| adapter_failure(path, error.to_string());
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io)?;
    let before = file.metadata().map_err(io)?;
    if !before.is_file() {
        return Err(adapter_failure(path, format!("Not a regular file: {path}")));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io(error)),
        }
    }
    let after = file.metadata().map_err(io)?;
    let current = std::fs::symlink_metadata(path).map_err(io)?;
    if fingerprint(&before) != fingerprint(&after) || fingerprint(&before) != fingerprint(&current)
    {
        return Err(changed());
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest == sha256 {
        Ok(())
    } else {
        Err(AnalysisError::evidence_integrity(
            "Native call observation target digest changed after session binding",
        ))
    }
}
