//! Non-symlink-following directory container reader.
//!
//! Compatibility owner: `src/artifacts/DirectoryArtifactReader.ts`. Built on
//! `rea_host::fs::stable_directory::DirectoryReader`, which anchors traversal to an
//! open root descriptor, revalidates containment and entry identity, reads
//! entries no-follow, and fails closed off Unix. Executable marking mirrors
//! `hostExecutableMarking`.
use super::reader::{ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure};
use rea_core::JsString;
use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryError, DirectoryReader,
};
use std::collections::HashMap;

const MAX_DIRECTORY_ENTRIES: usize = 2_000_000;

/// `hostExecutableMarking`.
#[cfg(unix)]
fn host_executable_marking(absolute: &std::path::Path, _is_file: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(absolute)
        .map(|metadata| (metadata.mode() & 0o111) != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn host_executable_marking(absolute: &std::path::Path, is_file: bool) -> bool {
    if !is_file {
        return false;
    }

    let lower = absolute
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase());
    matches!(
        lower.as_deref(),
        Some("bat") | Some("cmd") | Some("com") | Some("exe")
    )
}

pub struct DirectoryArtifactReader {
    root_path: String,
    reader: Option<DirectoryReader>,
    entries: HashMap<String, DirectoryEntry>,
}

impl DirectoryArtifactReader {
    pub fn new(root: &str) -> Self {
        Self {
            root_path: root.to_owned(),
            reader: None,
            entries: HashMap::new(),
        }
    }

    fn ensure_open(&mut self) -> Result<&DirectoryReader, ReaderFailure> {
        if self.reader.is_none() {
            let reader = DirectoryReader::open(std::path::Path::new(&self.root_path))
                .map_err(|error| translate(&error))?;
            self.reader = Some(reader);
        }
        Ok(self.reader.as_ref().expect("reader opened above"))
    }
}

fn translate(error: &DirectoryError) -> ReaderFailure {
    match error {
        DirectoryError::Cancelled(_) => ReaderFailure::new("cancelled", error.to_string()),
        DirectoryError::InvalidRoot | DirectoryError::InvalidRelativePath => {
            ReaderFailure::new("path", error.to_string())
        }
        DirectoryError::Changed(_) => ReaderFailure::new("integrity", error.to_string()),
        DirectoryError::Limit { .. } | DirectoryError::LimitBytes { .. } => {
            ReaderFailure::new("limit", error.to_string())
        }
        DirectoryError::Unsupported(_) => ReaderFailure::new("unavailable", error.to_string()),
        DirectoryError::Cleanup { .. } | DirectoryError::Io { .. } => {
            ReaderFailure::new("io", error.to_string())
        }
    }
}

impl ArtifactReader for DirectoryArtifactReader {
    fn format(&self) -> &'static str {
        "directory"
    }

    fn entries(
        &mut self,
        cancellation: &Cancellation,
        _omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        self.ensure_open()?;
        let reader = self.reader.as_ref().expect("reader opened above");
        let canonical = reader.root().canonical_path.clone();
        let listed = reader
            .entries(MAX_DIRECTORY_ENTRIES, cancellation)
            .map_err(|error| translate(&error))?;
        let mut out = Vec::with_capacity(listed.len());
        self.entries.clear();
        for entry in listed {
            let kind = match entry.kind {
                DirectoryEntryKind::Regular => "file",
                DirectoryEntryKind::Directory => "directory",
                DirectoryEntryKind::Symlink => "symlink",
            };
            let absolute = canonical.join(&entry.path);
            let adapter_key = absolute
                .to_str()
                .ok_or_else(|| {
                    ReaderFailure::new(
                        "path",
                        format!("Directory entry path is not representable as UTF-8: {absolute:?}"),
                    )
                })?
                .to_owned();
            let executable = host_executable_marking(&absolute, kind == "file");
            let declared_size = if kind == "file" {
                Some(entry.identity.bytes)
            } else {
                None
            };
            out.push(ArtifactEntry {
                path: JsString::from(entry.path.clone()),
                kind,
                declared_size,
                compressed_size: None,
                executable,
                encrypted: false,
                byte_offset: None,
                declared_sha256: None,
                unpacked: false,
                limitations: if kind == "symlink" {
                    vec!["Symlink target was not followed or disclosed.".to_owned()]
                } else {
                    Vec::new()
                },
                adapter_key: JsString::from(adapter_key.clone()),
            });
            self.entries.insert(adapter_key, entry);
        }
        Ok(out)
    }

    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        let directory_entry = self
            .entries
            .get(entry.adapter_key.as_str().unwrap_or_default())
            .cloned()
            .ok_or_else(|| {
                ReaderFailure::new(
                    "integrity",
                    format!("Directory entry changed before open: {}", entry.path),
                )
            })?;
        if directory_entry.kind != DirectoryEntryKind::Regular {
            return Err(ReaderFailure::new(
                "format",
                "Only regular files can be opened",
            ));
        }
        let reader = self
            .reader
            .as_ref()
            .ok_or_else(|| ReaderFailure::new("io", "Directory reader is not initialized"))?;
        let size = directory_entry.identity.bytes as usize;
        reader
            .read_entry_bounded(&directory_entry, size, cancellation)
            .map_err(|error| translate(&error))
    }

    fn close(&mut self) -> Result<(), ReaderFailure> {
        // DirectoryReader releases its root descriptor on drop; there is no
        // retained-handle cleanup that can fail for a read-only traversal.
        self.reader = None;
        self.entries.clear();
        Ok(())
    }
}
