//! One decode's provider-owned workspace: the input snapshot, bounded output
//! readback and the decoded-tree inventory.
//!
//! Compatibility owners: `src/apktool/ApktoolWorkspace.ts` and
//! `src/apktool/ApktoolDecodedInventory.ts`. The private root is owned by
//! `common::workspace::PrivateRoot`; its removal is retried on a failed close.

use crate::common::files::{self, FileState, StableFileError};
use crate::common::workspace::PrivateRoot;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::locale::{self, TableClass};

/// The identity of the admitted input snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// A failed text read that must surface as a producer failure.
#[derive(Debug)]
pub enum ReadError {
    /// Cancellation observed at a checkpoint.
    Cancelled,
    /// The output changed while being read, or decoded to invalid UTF-8.
    Protocol(String),
    /// A physical I/O failure.
    Io { path: String, error: io::Error },
}

/// The bounded result of a text read.
pub struct TextRead {
    pub text: Option<String>,
    pub truncated: bool,
    pub source_bytes: usize,
}

/// The workspace over one private runtime root.
pub struct Workspace {
    root: PrivateRoot,
    snapshot: Option<SnapshotIdentity>,
}

impl Workspace {
    pub fn new(root: PrivateRoot) -> Self {
        Self {
            root,
            snapshot: None,
        }
    }

    pub fn path(&self) -> &Path {
        self.root.path()
    }

    pub fn snapshot(&self) -> Option<&SnapshotIdentity> {
        self.snapshot.as_ref()
    }

    /// Remove the owned root. On failure the root is returned so its owner can
    /// retain it for a later retry.
    pub fn release(mut self) -> Result<(), PrivateRoot> {
        match self.root.close() {
            Ok(()) => Ok(()),
            Err(_) => Err(self.root),
        }
    }

    /// Stream the admitted input into an owner-only `input.apk` snapshot and
    /// record its identity. The source is read once through a stable
    /// descriptor and re-verified; the copy is re-digested.
    pub fn snapshot_input(
        &mut self,
        path: &str,
        operation: &str,
        cancellation: &Cancellation,
    ) -> Result<SnapshotIdentity, AnalysisError> {
        let source = Path::new(path);
        let digest = files::hash_stable_file(source, cancellation)
            .map_err(|error| snapshot_failure(operation, path, error))?;
        let destination = self.root.path().join("input.apk");
        files::copy_snapshot(source, &destination, &digest.sha256, cancellation).map_err(
            |error| match error {
                files::SnapshotError::File(StableFileError::Cancelled(_)) => {
                    AnalysisError::cancelled(operation)
                }
                files::SnapshotError::Changed(message) => input_changed(operation, message),
                files::SnapshotError::File(file_error) => {
                    snapshot_failure(operation, path, file_error)
                }
            },
        )?;
        files::make_read_only(&destination).map_err(|error| {
            AnalysisError::protocol(format!(
                "apktool snapshot could not be sealed read-only: {}",
                files::node_io_message(&error, "chmod", &destination.display().to_string())
            ))
        })?;
        let identity = SnapshotIdentity {
            path: path.to_owned(),
            bytes: digest.bytes,
            sha256: digest.sha256,
        };
        self.snapshot = Some(identity.clone());
        Ok(identity)
    }

    /// Read one decoded output file up to `budget` bytes, rejecting a
    /// non-regular or changed file. A missing file returns `text: None`.
    pub fn read_text(
        &self,
        path: &Path,
        budget: usize,
        cancellation: &Cancellation,
    ) -> Result<TextRead, ReadError> {
        if cancellation.reason().is_some() {
            return Err(ReadError::Cancelled);
        }
        let (mut file, initial) = match files::open_regular(path, false, cancellation) {
            Ok(opened) => opened,
            Err(StableFileError::Cancelled(_)) => return Err(ReadError::Cancelled),
            Err(error @ StableFileError::Io { .. }) if error.code() == Some("ENOENT") => {
                return Ok(TextRead {
                    text: None,
                    truncated: false,
                    source_bytes: 0,
                });
            }
            Err(StableFileError::NotRegular { path, directory }) => {
                return Err(ReadError::Protocol(if directory {
                    format!("Apktool output is a directory, not a file: {path}")
                } else {
                    format!("Apktool output is not a regular file: {path}")
                }));
            }
            Err(StableFileError::Changed { path }) => {
                return Err(ReadError::Protocol(format!(
                    "Apktool output changed while being read: {path}"
                )));
            }
            Err(StableFileError::Io { path, error }) => return Err(ReadError::Io { path, error }),
        };

        let capacity = budget + 1;
        let mut buffer = vec![0u8; capacity];
        let mut length = 0usize;
        while length < capacity {
            if cancellation.reason().is_some() {
                return Err(ReadError::Cancelled);
            }
            match file.read(&mut buffer[length..]) {
                Ok(0) => break,
                Ok(read) => length += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(ReadError::Io {
                        path: path.display().to_string(),
                        error,
                    });
                }
            }
        }
        let current = file
            .metadata()
            .map(|metadata| FileState::of(&metadata))
            .map_err(|error| ReadError::Io {
                path: path.display().to_string(),
                error,
            })?;
        if !initial.same_regular(&current) {
            return Err(ReadError::Protocol(format!(
                "Apktool output changed while being read: {}",
                path.display()
            )));
        }
        let truncated = length > budget;
        let source_bytes = length.min(budget);
        match std::str::from_utf8(&buffer[..source_bytes]) {
            Ok(text) => Ok(TextRead {
                text: Some(text.to_owned()),
                truncated,
                source_bytes,
            }),
            // A truncated prefix may split a trailing multi-byte sequence; the
            // streaming decoder keeps the valid leading portion.
            Err(_) if truncated => Ok(TextRead {
                text: Some(valid_prefix(&buffer[..source_bytes])),
                truncated,
                source_bytes,
            }),
            Err(_) => Err(ReadError::Protocol(format!(
                "apktool produced invalid UTF-8 in {}",
                path.display()
            ))),
        }
    }
}

/// Decode the longest valid UTF-8 prefix of a (possibly split) byte slice.
fn valid_prefix(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(error) => String::from_utf8_lossy(&bytes[..error.valid_up_to()]).into_owned(),
    }
}

fn snapshot_failure(operation: &str, path: &str, error: StableFileError) -> AnalysisError {
    match &error {
        StableFileError::Cancelled(_) => AnalysisError::cancelled(operation),
        StableFileError::Changed { .. } => input_changed(
            operation,
            format!("The selected APK changed while being copied: {path}"),
        ),
        StableFileError::NotRegular { .. } | StableFileError::Io { .. } => {
            input_changed(operation, error.to_string())
        }
    }
}

fn input_changed(operation: &str, message: String) -> AnalysisError {
    AnalysisError::input_message(
        operation,
        message.clone(),
        vec![rea_core::analysis_error::InputIssue {
            path: vec![serde_json::Value::String("path".into())],
            reason: "invalid_value",
            message: Some(message),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}

/// A strings table that could not be read as a regular file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StringsTableOmission {
    pub path: String,
    pub kind: String,
}

/// The decoded-tree inventory (`DecodedInventory`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DecodedInventory {
    pub count: u64,
    pub capped: bool,
    pub locales: Vec<String>,
    pub other_strings_tables: Vec<String>,
    pub unreadable_strings_tables: Vec<StringsTableOmission>,
}

/// `countDecodedFiles(workspace, root, signal, maximumEntries)`: count files
/// over a bounded traversal, classifying decoded string tables.
pub fn count_decoded_files(
    root: &Path,
    cancellation: &Cancellation,
    maximum_entries: u64,
) -> Result<DecodedInventory, (AnalysisError, DecodedInventory)> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let strings_regex =
        RE.get_or_init(|| regex::Regex::new(r"^res/(values(?:-([^/]*))?)/strings\.xml$").unwrap());

    let mut inventory = DecodedInventory::default();
    let mut visited: u64 = 0;

    let observe_table = |relative: &str, kind: &str, inventory: &mut DecodedInventory| {
        let Some(captures) = strings_regex.captures(relative) else {
            return;
        };
        if kind != "file" {
            inventory
                .unreadable_strings_tables
                .push(StringsTableOmission {
                    path: relative.to_owned(),
                    kind: kind.to_owned(),
                });
            return;
        }
        let Some(suffix) = captures.get(2) else {
            return;
        };
        match locale::classify_strings_table(suffix.as_str()) {
            TableClass::Locale(found) => inventory.locales.push(found),
            TableClass::Other => inventory.other_strings_tables.push(
                captures
                    .get(1)
                    .map_or(String::new(), |matched| matched.as_str().to_owned()),
            ),
        }
    };

    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut capped = false;
    let mut failure: Option<AnalysisError> = None;
    'walk: while let Some(directory) = stack.pop() {
        if cancellation.reason().is_some() {
            failure = Some(AnalysisError::cancelled("decode_android_resources"));
            break;
        }
        let read_dir = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                failure = Some(AnalysisError::protocol(format!(
                    "Apktool decoded tree could not be enumerated: {}",
                    files::node_io_message(&error, "scandir", &directory.display().to_string())
                )));
                break;
            }
        };
        let mut entries: Vec<std::fs::DirEntry> = Vec::new();
        for entry in read_dir {
            match entry {
                Ok(entry) => entries.push(entry),
                Err(error) => {
                    failure = Some(AnalysisError::protocol(format!(
                        "Apktool decoded tree could not be enumerated: {}",
                        files::node_io_message(&error, "readdir", &directory.display().to_string())
                    )));
                    break 'walk;
                }
            }
        }
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if visited >= maximum_entries {
                capped = true;
                break 'walk;
            }
            visited += 1;
            let entry_path = entry.path();
            let relative = relative_slash_path(root, &entry_path);
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    observe_table(&relative, "unknown", &mut inventory);
                    continue;
                }
            };
            if file_type.is_dir() {
                stack.push(entry_path);
            } else if file_type.is_file() {
                observe_table(&relative, "file", &mut inventory);
                inventory.count += 1;
            } else if file_type.is_symlink() {
                observe_table(&relative, "symlink", &mut inventory);
            } else {
                observe_table(&relative, "special", &mut inventory);
            }
        }
    }

    inventory.capped = capped;
    inventory.locales.sort();
    inventory.other_strings_tables.sort();
    inventory
        .unreadable_strings_tables
        .sort_by(|a, b| a.path.cmp(&b.path));

    match failure {
        Some(error) => Err((error, inventory)),
        None => Ok(inventory),
    }
}

/// The POSIX-style relative path of `entry` under `root` using `/` separators.
fn relative_slash_path(root: &Path, entry: &Path) -> String {
    let relative = entry.strip_prefix(root).unwrap_or(entry);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
