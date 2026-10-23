//! Pre-run and post-run artifact digests.
//!
//! Compatibility owner: `digestFile` / `statWithDeadline` in
//! `src/application/reverse/ReverseEngineeringService.ts`. The digest is the
//! streamed SHA-256 of a regular file, bounded by the shared command deadline
//! and caller cancellation; the caller-visible error codes (`EACCES`,
//! `EPERM`, `ETIMEDOUT`, `EINVAL`, ...) drive the service's failure mapping.
use crate::node;
use rea_core::cancellation::Cancellation;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::{Duration, Instant};

/// A digest failure carrying Node's error code where one is known.
#[derive(Clone, Debug)]
pub struct DigestError {
    pub code: Option<&'static str>,
    /// True when caller cancellation interrupted the digest.
    pub cancelled: bool,
}

impl DigestError {
    fn code(code: &'static str) -> Self {
        Self {
            code: Some(code),
            cancelled: false,
        }
    }

    fn cancelled() -> Self {
        Self {
            code: None,
            cancelled: true,
        }
    }
}

/// `digestFile(path, signal, stat)` → lowercase hex SHA-256.
pub fn digest_file(
    path: &str,
    cancellation: &Cancellation,
    timeout_ms: u64,
) -> Result<String, DigestError> {
    if cancellation.reason().is_some() {
        return Err(DigestError::cancelled());
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    // `statWithDeadline` then the regular-file guard.
    let metadata = std::fs::metadata(path).map_err(|error| classify(&error))?;
    if !metadata.is_file() {
        // `Object.assign(new Error(...), { code: "EINVAL" })`.
        return Err(DigestError::code("EINVAL"));
    }
    let mut file = std::fs::File::open(path).map_err(|error| classify(&error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if cancellation.reason().is_some() {
            return Err(DigestError::cancelled());
        }
        if Instant::now() >= deadline {
            return Err(DigestError::code("ETIMEDOUT"));
        }
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(classify(&error)),
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn classify(error: &std::io::Error) -> DigestError {
    DigestError {
        code: node::error_code(error),
        cancelled: false,
    }
}
