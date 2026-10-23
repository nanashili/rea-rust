//! Digest-verified Mach-O byte snapshot binding for `inspect_signature`.
//!
//! Compatibility owner: `src/native/SignatureTargetBinding.ts`
//! (`withSignatureTarget`, `bindSignatureTarget`, `verifySignatureTarget`,
//! the private runtime root, and session-owned cleanup retention).
//!
//! The snapshot is a private copy whose bytes are verified against the
//! analyzed target's registered SHA-256. codesign runs against the copy, never
//! the mutable source path, and the source identity is re-checked before and
//! after every command so a later capture can never read another version.

use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_mcp::SessionResource;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;

use super::super::IDENTITY_ID;

const OPERATION: &str = "inspect_signature";
/// Copy/hash buffer, matching the 64 KiB chunk the TypeScript binder uses.
const CHUNK_BYTES: usize = 64 * 1024;

/// A binding of commands to the selected executable's registered content.
pub(in crate::native_macos) struct SignatureTargetBinding {
    pub identity: String,
    pub snapshot_path: String,
}

/// Session-owned retention of private roots whose cleanup failed, mirroring the
/// `ArtifactResourceScope` ownership the TypeScript binder keeps on failure.
#[derive(Default)]
pub(in crate::native_macos) struct SignatureCleanup {
    pending: Mutex<Vec<PathBuf>>,
}

impl SignatureCleanup {
    fn retain(&self, root: PathBuf) {
        self.pending
            .lock()
            .expect("signature cleanup lock")
            .push(root);
    }

    fn retry(&self) -> Vec<PathBuf> {
        let mut pending = self.pending.lock().expect("signature cleanup lock");
        let mut failures = Vec::new();
        let retained: Vec<PathBuf> = pending.drain(..).collect();
        for root in retained {
            if fs::remove_dir_all(&root).is_err() && root.exists() {
                failures.push(root);
            }
        }
        *pending = failures.clone();
        failures
    }
}

impl SessionResource for SignatureCleanup {
    fn close(&self) -> Result<(), AnalysisError> {
        let failures = self.retry();
        if failures.is_empty() {
            return Ok(());
        }
        let resources: Vec<String> = failures
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        Err(AnalysisError::provider_adapter(IDENTITY_ID, OPERATION)
            .with_cleanup("Signature snapshot roots could not be removed", resources))
    }
}

/// `withSignatureTarget(...)`: create a private root, bind a digest-verified
/// snapshot, run `inspect`, then release the root. A failed release is retained
/// for shutdown retry by `cleanup` instead of being dropped.
pub(in crate::native_macos) fn with_signature_target<T>(
    target: &rea_analysis::BinaryTarget,
    cleanup: &Arc<SignatureCleanup>,
    cancellation: &Cancellation,
    inspect: impl FnOnce(&SignatureTargetBinding) -> Result<T, AnalysisError>,
) -> Result<T, AnalysisError> {
    check_cancelled(cancellation)?;
    let root = create_private_root(target)?;
    let snapshot_path = root.join(base_name(&target.path));

    let bound = bind_signature_target(target, &snapshot_path, cancellation);
    let result = match bound {
        Ok(binding) => inspect(&binding),
        Err(error) => Err(error),
    };

    // Release the private root on every path; retain it on cleanup failure.
    if fs::remove_dir_all(&root).is_err() && root.exists() {
        cleanup.retain(root);
    }

    if result.is_ok()
        && let Some(reason) = cancellation.reason()
    {
        return Err(AnalysisError::cancelled(OPERATION).with_user_message(reason.to_owned()));
    }
    result
}

/// Create the signature inspection's private runtime root
/// (`PrivateRuntimeRoot.create({ prefix: "rea-signature-" })`).
fn create_private_root(target: &rea_analysis::BinaryTarget) -> Result<PathBuf, AnalysisError> {
    tempfile::Builder::new()
        .prefix("rea-signature-")
        .tempdir()
        .map(tempfile::TempDir::keep)
        .map_err(|cause| snapshot_failure(target, "create", &cause.to_string()))
}

/// `bindSignatureTarget(...)`: hash and copy the same descriptor bytes, and
/// reject any drift in the source identity across the copy.
fn bind_signature_target(
    target: &rea_analysis::BinaryTarget,
    snapshot_path: &Path,
    cancellation: &Cancellation,
) -> Result<SignatureTargetBinding, AnalysisError> {
    check_cancelled(cancellation)?;
    let before =
        fs::symlink_metadata(&target.path).map_err(|cause| read_failure(target, &cause))?;
    check_cancelled(cancellation)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(changed_target(
            target,
            &format!(
                "Signature target is no longer a regular file: {}",
                target.path
            ),
        ));
    }

    let mut source = fs::File::open(&target.path).map_err(|cause| read_failure(target, &cause))?;
    let opened = source
        .metadata()
        .map_err(|cause| read_failure(target, &cause))?;
    check_cancelled(cancellation)?;
    if identity(&opened) != identity(&before) {
        return Err(changed_target(
            target,
            &format!("Signature target changed before open: {}", target.path),
        ));
    }

    let mut snapshot = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(snapshot_path)
        .map_err(|cause| snapshot_failure(target, "create-file", &cause.to_string()))?;

    let observed = copy_signature_bytes(target, &mut source, &mut snapshot, cancellation)?;
    if observed != target.sha256 {
        return Err(changed_target(
            target,
            &format!(
                "Signature target digest changed: {}; expected {}, observed {observed}",
                target.path, target.sha256
            ),
        ));
    }

    let after = source
        .metadata()
        .map_err(|cause| read_failure(target, &cause))?;
    let current =
        fs::symlink_metadata(&target.path).map_err(|cause| read_failure(target, &cause))?;
    check_cancelled(cancellation)?;
    if identity(&after) != identity(&opened) || identity(&current) != identity(&opened) {
        return Err(changed_target(
            target,
            &format!(
                "Signature target changed while establishing its version: {}",
                target.path
            ),
        ));
    }

    // `snapshot.chmod(0o400)` — seal the private copy read-only.
    seal_readonly(&snapshot);

    Ok(SignatureTargetBinding {
        identity: identity(&opened),
        snapshot_path: snapshot_path.to_string_lossy().into_owned(),
    })
}

/// `copySignatureBytes(...)`: hash and copy the descriptor bytes in bounded
/// chunks, rejecting a truncation during hashing.
fn copy_signature_bytes(
    target: &rea_analysis::BinaryTarget,
    source: &mut fs::File,
    snapshot: &mut fs::File,
    cancellation: &Cancellation,
) -> Result<String, AnalysisError> {
    use std::io::Write as _;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    loop {
        check_cancelled(cancellation)?;
        let read = source
            .read(&mut buffer)
            .map_err(|cause| snapshot_failure(target, "read", &cause.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        snapshot
            .write_all(&buffer[..read])
            .map_err(|cause| snapshot_failure(target, "write", &cause.to_string()))?;
    }
    Ok(hex(&hasher.finalize()))
}

/// `verifySignatureTarget(...)`: reject source drift across captures.
pub(in crate::native_macos) fn verify_signature_target(
    target: &rea_analysis::BinaryTarget,
    binding: &SignatureTargetBinding,
    cancellation: &Cancellation,
) -> Result<(), AnalysisError> {
    check_cancelled(cancellation)?;
    let current = match fs::symlink_metadata(&target.path) {
        Ok(current) => current,
        Err(cause) => return Err(read_failure(target, &cause)),
    };
    check_cancelled(cancellation)?;
    if current.is_file() && identity(&current) == binding.identity {
        Ok(())
    } else {
        Err(changed_target(
            target,
            &format!(
                "Signature target changed during inspection: {}",
                target.path
            ),
        ))
    }
}

/// `identity(stat)`: `dev:ino:size:mtimeNs:ctimeNs`.
fn identity(metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        format!(
            "{}:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.size(),
            nanoseconds(metadata.mtime(), metadata.mtime_nsec()),
            nanoseconds(metadata.ctime(), metadata.ctime_nsec()),
        )
    }
    #[cfg(not(unix))]
    {
        // Off Unix the native tools are already unavailable; keep a compilable,
        // drift-sensitive identity from the portable metadata.
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        format!("{}:{modified}", metadata.len())
    }
}

#[cfg(unix)]
fn nanoseconds(seconds: i64, nanos: i64) -> i128 {
    i128::from(seconds) * 1_000_000_000 + i128::from(nanos)
}

fn seal_readonly(file: &fs::File) {
    if let Ok(metadata) = file.metadata() {
        let mut permissions = metadata.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(0o400);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(true);
        let _ = file.set_permissions(permissions);
    }
}

fn base_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn check_cancelled(cancellation: &Cancellation) -> Result<(), AnalysisError> {
    match cancellation.reason() {
        Some(_) => Err(AnalysisError::cancelled(OPERATION)),
        None => Ok(()),
    }
}

fn changed_target(target: &rea_analysis::BinaryTarget, reason: &str) -> AnalysisError {
    AnalysisError::artifact_changed(OPERATION, target.path.clone(), reason.to_owned())
}

/// `signatureReadFailure(target, cause)` for a filesystem error.
fn read_failure(target: &rea_analysis::BinaryTarget, cause: &std::io::Error) -> AnalysisError {
    use std::io::ErrorKind;
    match cause.kind() {
        ErrorKind::PermissionDenied => {
            AnalysisError::access_denied(OPERATION, target.path.clone(), "EACCES")
        }
        ErrorKind::NotFound => AnalysisError::artifact_changed(
            OPERATION,
            target.path.clone(),
            format!(
                "Registered signature target is no longer readable (ENOENT): {}",
                target.path
            ),
        ),
        _ => {
            let mut diagnostics = serde_json::Map::new();
            diagnostics.insert("path".into(), serde_json::json!(target.path));
            diagnostics.insert("phase".into(), serde_json::json!("target-version-binding"));
            diagnostics.insert("reason".into(), serde_json::json!(cause.to_string()));
            AnalysisError::provider_adapter(IDENTITY_ID, OPERATION).with_diagnostics(diagnostics)
        }
    }
}

/// `snapshotFailure(target, phase, cause)`.
fn snapshot_failure(
    target: &rea_analysis::BinaryTarget,
    phase: &str,
    reason: &str,
) -> AnalysisError {
    let mut diagnostics = serde_json::Map::new();
    diagnostics.insert("path".into(), serde_json::json!(target.path));
    diagnostics.insert(
        "phase".into(),
        serde_json::json!(format!("signature-snapshot-{phase}")),
    );
    diagnostics.insert("reason".into(), serde_json::json!(reason));
    AnalysisError::provider_adapter(IDENTITY_ID, OPERATION).with_diagnostics(diagnostics)
}

/// Canonical (symlink-resolved) path, used to strip codesign's echoed path.
pub(in crate::native_macos) fn canonical_path(path: &str) -> Vec<String> {
    match fs::canonicalize(path) {
        Ok(resolved) => vec![resolved.to_string_lossy().into_owned()],
        Err(_) => Vec::new(),
    }
}
