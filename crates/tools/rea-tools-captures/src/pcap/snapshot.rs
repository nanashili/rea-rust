//! An owned capture copy and the descriptors needed to release it safely.
//!
//! Compatibility owner: `src/pcap/PcapSnapshot.ts`. A private runtime root
//! holds a read-only copy of the selected capture plus a private Wireshark
//! configuration directory. Acquisition and post-analysis verification both
//! revalidate byte identity; only bytes present in the owned copy are examined.
use crate::node::{self, FsError};
use crate::producer::make_private_directory;
use crate::runtime::RuntimeRoot;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};

const OPERATION: &str = "inspect_pcap_capture";
const MAX_CAPTURE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Acquired capture identity with its digest.
#[derive(Clone, Debug)]
pub struct CaptureIdentity {
    pub bytes: u64,
    pub sha256: String,
}

/// Stable regular-file identity facts compared across reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileState {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    mtime_ns: i128,
}

fn file_state(metadata: &fs::Metadata) -> FileState {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileState {
            len: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
        }
    }
    #[cfg(not(unix))]
    {
        let mtime_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos() as i128)
            .unwrap_or_default();
        FileState {
            len: metadata.len(),
            mtime_ns,
        }
    }
}

/// An owned private capture snapshot.
pub struct PcapSnapshot {
    root: RuntimeRoot,
    pub path: String,
    pub configuration_path: String,
}

impl PcapSnapshot {
    /// `PcapSnapshot.create`: a private runtime root under the session tmpdir.
    pub fn create(
        environment: &std::collections::HashMap<String, String>,
    ) -> Result<Self, AnalysisError> {
        let root = RuntimeRoot::create("rea-pcap-", environment).map_err(|error| {
            AnalysisError::resource_constraint(
                OPERATION,
                "file-size",
                format!("Cannot allocate the owned capture workspace ({error})"),
                None,
            )
        })?;
        let path = node::join(root.path(), "capture.pcap");
        let configuration_path = node::join(root.path(), "configuration");
        Ok(Self {
            root,
            path,
            configuration_path,
        })
    }

    fn access_error(path: &str, error: &std::io::Error) -> Option<AnalysisError> {
        match node::error_code(error) {
            Some(code @ ("EACCES" | "EPERM")) => {
                Some(AnalysisError::access_denied(OPERATION, path, code))
            }
            _ => None,
        }
    }

    /// `capture`: copy the selected file into the owned root, verifying identity.
    pub fn capture(
        &self,
        path: &str,
        cancellation: &Cancellation,
    ) -> Result<CaptureIdentity, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        make_private_directory(&self.configuration_path).map_err(|error| {
            AnalysisError::resource_constraint(
                OPERATION,
                "file-size",
                format!("Owned capture snapshot I/O failed ({})", error.message),
                None,
            )
        })?;

        let source_meta =
            fs::symlink_metadata(path).map_err(|error| self.read_input_error(path, &error))?;
        if !source_meta.file_type().is_file() {
            return Err(crate::errors::input_issue(
                OPERATION,
                vec![crate::errors::segment("path")],
                "invalid_value",
                format!("Expected a regular file without a symlink: {path}"),
            ));
        }
        let before = file_state(&source_meta);
        if before.len > MAX_CAPTURE_BYTES {
            return Err(AnalysisError::resource_constraint(
                OPERATION,
                "file-size",
                "Capture exceeds the owned-snapshot disk budget",
                Some(serde_json::json!({ "max_capture_bytes": MAX_CAPTURE_BYTES })),
            ));
        }

        let mut source =
            fs::File::open(path).map_err(|error| self.read_input_error(path, &error))?;
        let mut destination = open_exclusive(&self.path, 0o600).map_err(|error| {
            AnalysisError::resource_constraint(
                OPERATION,
                "file-size",
                format!("Owned capture snapshot I/O failed ({})", error.message),
                None,
            )
        })?;

        let mut buffer = vec![0_u8; 64 * 1024];
        let mut hasher = Sha256::new();
        let mut copied: u64 = 0;
        loop {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(OPERATION));
            }
            let read = source
                .read(&mut buffer)
                .map_err(|error| self.read_input_error(path, &error))?;
            if read == 0 {
                break;
            }
            copied += read as u64;
            if copied > before.len {
                return Err(AnalysisError::artifact_changed(
                    OPERATION,
                    path,
                    "Capture grew during acquisition",
                ));
            }
            destination.write_all(&buffer[..read]).map_err(|error| {
                AnalysisError::resource_constraint(
                    OPERATION,
                    "file-size",
                    format!("Owned capture snapshot I/O failed ({error})"),
                    None,
                )
            })?;
            hasher.update(&buffer[..read]);
        }

        let after =
            fs::symlink_metadata(path).map_err(|error| self.read_input_error(path, &error))?;
        let after = file_state(&after);
        let selected = fs::symlink_metadata(path).map_err(|error| {
            if let Some(denied) = Self::access_error(path, &error) {
                denied
            } else {
                AnalysisError::artifact_changed(
                    OPERATION,
                    path,
                    "Selected path became unavailable during acquisition",
                )
            }
        })?;
        let selected = file_state(&selected);

        if copied != before.len || after != before || selected != before {
            return Err(AnalysisError::artifact_changed(
                OPERATION,
                path,
                "Capture identity or contents changed during acquisition",
            ));
        }

        drop(source);
        destination.flush().ok();
        drop(destination);
        set_read_only(&self.path, 0o400).map_err(|error| {
            AnalysisError::resource_constraint(
                OPERATION,
                "file-size",
                format!("Owned capture snapshot I/O failed ({})", error.message),
                None,
            )
        })?;
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        Ok(CaptureIdentity {
            bytes: copied,
            sha256: hex(hasher.finalize().as_slice()),
        })
    }

    fn read_input_error(&self, path: &str, error: &std::io::Error) -> AnalysisError {
        if let Some(denied) = Self::access_error(path, error) {
            return denied;
        }
        let message = FsError::from_io(error, "read", path).message;
        crate::errors::input_issue(
            OPERATION,
            vec![crate::errors::segment("path")],
            "invalid_value",
            format!("Cannot read selected capture {path}: {message}"),
        )
    }

    /// `verify`: recheck owned-copy byte identity after both tools.
    pub fn verify(
        &self,
        expected: &CaptureIdentity,
        selected_path: &str,
        cancellation: &Cancellation,
    ) -> Result<(), AnalysisError> {
        let changed = |reason: &str| {
            AnalysisError::artifact_changed(OPERATION, selected_path, reason.to_owned())
        };
        let before_meta = fs::symlink_metadata(&self.path).map_err(|_| {
            changed("Cannot establish the owned packet snapshot's post-analysis identity.")
        })?;
        if before_meta.file_type().is_symlink() || !before_meta.file_type().is_file() {
            return Err(changed(
                "Owned packet snapshot changed during tool analysis.",
            ));
        }
        let before = file_state(&before_meta);
        let mut file = fs::File::open(&self.path).map_err(|_| {
            changed("Cannot establish the owned packet snapshot's post-analysis identity.")
        })?;
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut hasher = Sha256::new();
        let mut bytes: u64 = 0;
        loop {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(OPERATION));
            }
            let read = file.read(&mut buffer).map_err(|_| {
                changed("Cannot establish the owned packet snapshot's post-analysis identity.")
            })?;
            if read == 0 {
                break;
            }
            bytes += read as u64;
            hasher.update(&buffer[..read]);
        }
        let after = file_state(&fs::symlink_metadata(&self.path).map_err(|_| {
            changed("Cannot establish the owned packet snapshot's post-analysis identity.")
        })?);
        if bytes != expected.bytes
            || hex(hasher.finalize().as_slice()) != expected.sha256
            || after != before
        {
            return Err(changed(
                "Owned packet snapshot changed during tool analysis.",
            ));
        }
        Ok(())
    }

    /// `close`: remove the owned root; a failed removal stays retryable.
    pub fn close(&mut self) -> Result<(), FsError> {
        self.root.close()
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn open_exclusive(path: &str, mode: u32) -> Result<fs::File, FsError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options
        .open(path)
        .map_err(|error| FsError::from_io(&error, "open", path))
}

fn set_read_only(path: &str, mode: u32) -> Result<(), FsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| FsError::from_io(&error, "chmod", path))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        let mut permissions = fs::metadata(path)
            .map_err(|error| FsError::from_io(&error, "stat", path))?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)
            .map_err(|error| FsError::from_io(&error, "chmod", path))
    }
}
