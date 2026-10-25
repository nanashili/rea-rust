//! macOS host ownership for read-only Apple asset catalog inspection.
//!
//! This module deliberately stops at the host boundary. It admits bundle
//! entries through `DirectoryReader`, keeps their native identities for
//! revalidation, and owns the `assetutil` child until output and termination
//! have settled.

#![cfg(target_os = "macos")]

use crate::fs::stable_directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryEntryPolicy, DirectoryError, DirectoryReader,
};
use rea_core::cancellation::Cancellation;
use std::{
    ffi::OsStr,
    fmt,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub const ASSETUTIL_PATH: &str = "/usr/bin/assetutil";
pub const MAX_CATALOG_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_BUNDLE_ENTRIES: usize = 100_000;
// Installed Xcode 27.0 contains 166,799 entries on the benchmark host. Keep a
// separate bounded observation budget because only Assets.car files are
// admissible catalog candidates.
pub const MAX_BUNDLE_OBSERVATIONS: usize = 200_000;
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetCatalogEntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetCatalogEntry {
    pub path: String,
    pub adapter_path: PathBuf,
    pub kind: AssetCatalogEntryKind,
    pub identity: crate::fs::stable_file::Fingerprint,
    pub declared_size: Option<u64>,
}

pub struct AssetCatalogBundle {
    reader: DirectoryReader,
}

impl AssetCatalogBundle {
    pub fn open(path: &Path) -> Result<Self, AssetCatalogHostError> {
        Ok(Self {
            reader: DirectoryReader::open(path).map_err(AssetCatalogHostError::directory)?,
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.reader.root().canonical_path
    }

    pub fn entries(
        &self,
        cancellation: &Cancellation,
    ) -> Result<Vec<AssetCatalogEntry>, AssetCatalogHostError> {
        self.reader
            .entries_with_policy(
                MAX_BUNDLE_ENTRIES,
                MAX_BUNDLE_OBSERVATIONS,
                cancellation,
                |entry| DirectoryEntryPolicy {
                    retain: is_assets_car(&entry.path),
                    descend: entry.kind == DirectoryEntryKind::Directory,
                },
            )
            .map_err(AssetCatalogHostError::directory)
            .map(|entries| {
                entries
                    .into_iter()
                    .filter(|entry| is_assets_car(&entry.path))
                    .map(|entry| self.describe(entry))
                    .collect()
            })
    }

    pub fn read_entry(
        &self,
        entry: &AssetCatalogEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, AssetCatalogHostError> {
        let directory_entry = self.inspect_expected(entry, cancellation)?;
        self.reader
            .read_entry_bounded(&directory_entry, MAX_CATALOG_BYTES, cancellation)
            .map_err(AssetCatalogHostError::directory)
    }

    pub fn current_identity(
        &self,
        entry: &AssetCatalogEntry,
        cancellation: &Cancellation,
    ) -> Result<crate::fs::stable_file::Fingerprint, AssetCatalogHostError> {
        Ok(self.inspect_expected(entry, cancellation)?.identity)
    }

    pub fn sha256_relative_path(
        &self,
        relative_path: &str,
        cancellation: &Cancellation,
    ) -> Result<String, AssetCatalogHostError> {
        let entry = self
            .reader
            .inspect_entry(relative_path, cancellation)
            .map_err(AssetCatalogHostError::directory)?
            .ok_or_else(|| AssetCatalogHostError::Changed(relative_path.to_owned()))?;
        if entry.kind != DirectoryEntryKind::Regular {
            return Err(AssetCatalogHostError::Changed(relative_path.to_owned()));
        }

        self.reader
            .open_entry(&entry, cancellation)
            .and_then(|mut file| file.sha256(cancellation))
            .map_err(AssetCatalogHostError::directory)
    }

    fn describe(&self, entry: DirectoryEntry) -> AssetCatalogEntry {
        let kind = match entry.kind {
            DirectoryEntryKind::Regular => AssetCatalogEntryKind::Regular,
            DirectoryEntryKind::Directory => AssetCatalogEntryKind::Directory,
            DirectoryEntryKind::Symlink => AssetCatalogEntryKind::Symlink,
        };
        let declared_size =
            (kind == AssetCatalogEntryKind::Regular).then_some(entry.identity.bytes);
        AssetCatalogEntry {
            adapter_path: self.reader.root().canonical_path.join(&entry.path),
            path: entry.path,
            kind,
            identity: entry.identity,
            declared_size,
        }
    }

    fn inspect_expected(
        &self,
        entry: &AssetCatalogEntry,
        cancellation: &Cancellation,
    ) -> Result<DirectoryEntry, AssetCatalogHostError> {
        let current = self
            .reader
            .inspect_entry(&entry.path, cancellation)
            .map_err(AssetCatalogHostError::directory)?
            .ok_or_else(|| AssetCatalogHostError::Changed(entry.path.clone()))?;
        if current.identity != entry.identity || entry_kind(current.kind) != entry.kind {
            return Err(AssetCatalogHostError::Changed(entry.path.clone()));
        }
        Ok(current)
    }
}

pub struct AssetutilCommand {
    executable: PathBuf,
}

impl Default for AssetutilCommand {
    fn default() -> Self {
        Self::new(Path::new(ASSETUTIL_PATH))
    }
}

impl AssetutilCommand {
    pub fn new(executable: &Path) -> Self {
        Self {
            executable: executable.to_owned(),
        }
    }

    pub fn inspect(
        &self,
        catalog_path: &Path,
        cancellation: &Cancellation,
    ) -> Result<String, AssetCatalogHostError> {
        if !self.executable.is_absolute() {
            return Err(AssetCatalogHostError::Unavailable(
                "assetutil executable path must be absolute".to_owned(),
            ));
        }
        if !self.executable.exists() {
            return Err(AssetCatalogHostError::Unavailable(format!(
                "assetutil is unavailable at {}",
                self.executable.display()
            )));
        }
        check_cancelled(cancellation)?;

        let mut child = Command::new(&self.executable)
            .arg("--info")
            .arg(catalog_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| AssetCatalogHostError::Unavailable(error.to_string()))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            AssetCatalogHostError::Io("assetutil stdout was not captured".to_owned())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            AssetCatalogHostError::Io("assetutil stderr was not captured".to_owned())
        })?;
        let (sender, receiver) = mpsc::channel();
        spawn_bounded_reader(stdout, sender.clone(), Stream::Stdout);
        spawn_bounded_reader(stderr, sender, Stream::Stderr);

        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let status = settle_child(&mut child, cancellation, deadline)?;
        let output = collect_output(receiver, cancellation)?;
        if output.overflowed {
            return Err(AssetCatalogHostError::Limit(format!(
                "assetutil output exceeds {MAX_CATALOG_BYTES} bytes"
            )));
        }
        if !status.success() {
            return Err(AssetCatalogHostError::Failed(format!(
                "assetutil exited with {}: {}",
                status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| AssetCatalogHostError::Failed("assetutil output was not UTF-8".to_owned()))
    }
}

#[derive(Debug)]
pub enum AssetCatalogHostError {
    Unavailable(String),
    Cancelled(String),
    Limit(String),
    Changed(String),
    Failed(String),
    Io(String),
}

impl AssetCatalogHostError {
    fn directory(error: DirectoryError) -> Self {
        match error {
            DirectoryError::Cancelled(reason) => Self::Cancelled(reason),
            DirectoryError::LimitBytes { maximum_bytes } => {
                Self::Limit(format!("directory read exceeds {maximum_bytes} bytes"))
            }
            DirectoryError::Limit { maximum_entries } => {
                Self::Limit(format!("directory entry limit exceeded: {maximum_entries}"))
            }
            DirectoryError::Changed(stage) => Self::Changed(stage.to_owned()),
            DirectoryError::Unsupported(reason) => Self::Unavailable(reason.to_owned()),
            other => Self::Io(other.to_string()),
        }
    }
}

impl fmt::Display for AssetCatalogHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => {
                write!(formatter, "asset catalog provider unavailable: {reason}")
            }
            Self::Cancelled(reason) => {
                write!(formatter, "asset catalog inspection cancelled: {reason}")
            }
            Self::Limit(reason) => write!(formatter, "asset catalog limit exceeded: {reason}"),
            Self::Changed(path) => write!(formatter, "asset catalog changed: {path}"),
            Self::Failed(reason) | Self::Io(reason) => formatter.write_str(reason),
        }
    }
}

impl std::error::Error for AssetCatalogHostError {}

fn is_assets_car(path: &str) -> bool {
    Path::new(path).file_name() == Some(OsStr::new("Assets.car"))
}

fn entry_kind(kind: DirectoryEntryKind) -> AssetCatalogEntryKind {
    match kind {
        DirectoryEntryKind::Regular => AssetCatalogEntryKind::Regular,
        DirectoryEntryKind::Directory => AssetCatalogEntryKind::Directory,
        DirectoryEntryKind::Symlink => AssetCatalogEntryKind::Symlink,
    }
}

fn check_cancelled(cancellation: &Cancellation) -> Result<(), AssetCatalogHostError> {
    match cancellation.reason() {
        Some(reason) => Err(AssetCatalogHostError::Cancelled(reason.to_owned())),
        None => Ok(()),
    }
}

enum Stream {
    Stdout,
    Stderr,
}

struct StreamOutput {
    stream: Stream,
    bytes: Vec<u8>,
    overflowed: bool,
}

fn spawn_bounded_reader<R>(mut reader: R, sender: mpsc::Sender<StreamOutput>, stream: Stream)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut overflowed = false;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if bytes.len().saturating_add(read) <= MAX_CATALOG_BYTES {
                        bytes.extend_from_slice(&buffer[..read]);
                    } else {
                        overflowed = true;
                    }
                }
                Err(_) => {
                    overflowed = true;
                    break;
                }
            }
        }
        let _ = sender.send(StreamOutput {
            stream,
            bytes,
            overflowed,
        });
    });
}

fn settle_child(
    child: &mut Child,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ExitStatus, AssetCatalogHostError> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| AssetCatalogHostError::Io(error.to_string()))?
        {
            return Ok(status);
        }
        if cancellation.reason().is_some() {
            terminate_child(child)?;
            return Err(AssetCatalogHostError::Cancelled(
                cancellation.reason().unwrap_or("cancelled").to_owned(),
            ));
        }
        if Instant::now() >= deadline {
            terminate_child(child)?;
            return Err(AssetCatalogHostError::Limit(
                "assetutil exceeded its 60 second deadline".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_child(child: &mut Child) -> Result<(), AssetCatalogHostError> {
    child.kill().map_err(|error| {
        AssetCatalogHostError::Io(format!("failed to terminate assetutil: {error}"))
    })?;
    child
        .wait()
        .map(|_| ())
        .map_err(|error| AssetCatalogHostError::Io(format!("failed to settle assetutil: {error}")))
}

struct CollectedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    overflowed: bool,
}

fn collect_output(
    receiver: mpsc::Receiver<StreamOutput>,
    cancellation: &Cancellation,
) -> Result<CollectedOutput, AssetCatalogHostError> {
    let mut output = CollectedOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        overflowed: false,
    };
    for _ in 0..2 {
        check_cancelled(cancellation)?;
        let stream = receiver
            .recv()
            .map_err(|error| AssetCatalogHostError::Io(error.to_string()))?;
        output.overflowed |= stream.overflowed;
        match stream.stream {
            Stream::Stdout => output.stdout = stream.bytes,
            Stream::Stderr => output.stderr = stream.bytes,
        }
    }
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_CATALOG_BYTES {
        output.overflowed = true;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use tempfile::tempdir;

    #[test]
    fn missing_assetutil_is_explicitly_unavailable() {
        let command = AssetutilCommand::new(Path::new("/definitely/missing/assetutil"));
        let error = command
            .inspect(Path::new("/tmp/Assets.car"), &Cancellation::default())
            .expect_err("missing provider must fail closed");
        assert!(matches!(error, AssetCatalogHostError::Unavailable(_)));
    }

    #[test]
    fn command_seam_returns_bounded_provider_output() {
        let directory = tempdir().expect("temporary directory");
        let script = directory.path().join("fake-assetutil");
        fs::write(&script, "#!/bin/sh\nprintf '[{}]'\n").expect("fake provider");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("executable");

        let output = AssetutilCommand::new(&script)
            .inspect(Path::new("/tmp/Assets.car"), &Cancellation::default())
            .expect("fake assetutil output");
        assert_eq!(output, "[{}]");
    }
}
