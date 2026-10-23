//! Host filesystem helpers for ADB acquisition and transfer.
//!
//! Compatibility owner: the output-directory, snapshot, publication and
//! cleanup helpers inside `src/adb/AdbProvider.ts` (which import
//! `src/filesystem/*`, `src/artifacts/*` and `src/adb/AdbInputSnapshot.ts`).
use crate::common::files::{self, FileState};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Identity (dev, ino, mode) of a created output directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputDirectoryIdentity {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
}

#[cfg(unix)]
fn directory_identity(metadata: &fs::Metadata) -> OutputDirectoryIdentity {
    use std::os::unix::fs::MetadataExt;
    OutputDirectoryIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
    }
}

#[cfg(windows)]
fn directory_identity(metadata: &fs::Metadata) -> OutputDirectoryIdentity {
    let state = FileState::of(metadata);
    OutputDirectoryIdentity {
        dev: state_dev(&state),
        ino: state_ino(&state),
        mode: 0,
    }
}

#[cfg(windows)]
fn state_dev(_state: &FileState) -> u64 {
    0
}

#[cfg(windows)]
fn state_ino(_state: &FileState) -> u64 {
    0
}

/// `path.resolve(directory)` against the current working directory.
pub fn resolve_path(path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&candidate))
            .unwrap_or(candidate)
    }
}

/// `prepareOutputDirectory(operation, directory)`.
pub fn prepare_output_directory(operation: &str, directory: &str) -> Result<String, AnalysisError> {
    let root = resolve_path(directory);
    let create_and_check = || -> std::io::Result<()> {
        fs::create_dir_all(&root)?;
        // access(root, W_OK): confirm the directory is writable.
        let metadata = fs::metadata(&root)?;
        if metadata.permissions().readonly() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "not writable",
            ));
        }
        Ok(())
    };
    match create_and_check() {
        Ok(()) => Ok(root.to_string_lossy().into_owned()),
        Err(_) => Err(AnalysisError::output(
            operation,
            format!(
                "The output directory is not writable or could not be created: {}",
                root.display()
            ),
        )),
    }
}

/// `refuseExistingTarget(operation, path)`.
pub fn refuse_existing_target(operation: &str, path: &Path) -> Option<AnalysisError> {
    if fs::symlink_metadata(path).is_ok() {
        Some(AnalysisError::output(
            operation,
            format!("The output file already exists: {}", path.display()),
        ))
    } else {
        None
    }
}

/// Create a directory and capture its verified identity.
pub fn create_directory_with_identity(
    path: &Path,
) -> Result<OutputDirectoryIdentity, std::io::Error> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "The package output directory already exists: {}",
                path.display()
            ),
        ));
    }
    fs::create_dir(path)?;
    let created = fs::symlink_metadata(path)?;
    if !created.is_dir() || created.file_type().is_symlink() {
        return Err(std::io::Error::other(format!(
            "The created package output is not a regular directory: {}",
            path.display()
        )));
    }
    Ok(directory_identity(&created))
}

/// `removeOwnedOutputDirectory(path, identity)`.
pub fn remove_owned_output_directory(
    path: &str,
    identity: Option<OutputDirectoryIdentity>,
) -> Result<(), String> {
    let Some(identity) = identity else {
        return Err(format!(
            "Cannot verify the created output directory identity; refusing to remove {path}"
        ));
    };
    let current = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let current_identity = directory_identity(&current);
    if !current.is_dir() || current.file_type().is_symlink() || current_identity != identity {
        return Err(format!(
            "The created output directory was replaced or changed; refusing to remove {path}"
        ));
    }
    fs::remove_dir_all(path).map_err(|error| error.to_string())
}

/// `reservePackageDestinations(...)`: reserve each local file name by creating
/// and removing a placeholder directory, refusing name collisions.
pub fn reserve_package_destinations(
    operation: &str,
    package_name: &str,
    package_directory: &Path,
    entries: &[(String, String)], // (file_name, device_path)
    captured_output: rea_core::analysis_error::CapturedOutput,
) -> Option<AnalysisError> {
    use crate::adb::device_output::display_device_path;
    let mut reservations: Vec<(PathBuf, String, String, OutputDirectoryIdentity)> = Vec::new();
    for (file_name, device_path) in entries {
        let path = package_directory.join(file_name);
        let created = (|| -> std::io::Result<OutputDirectoryIdentity> {
            fs::create_dir(&path)?;
            let created = fs::symlink_metadata(&path)?;
            if !created.is_dir() || created.file_type().is_symlink() {
                return Err(std::io::Error::other(format!(
                    "Could not reserve local filename {file_name}"
                )));
            }
            Ok(directory_identity(&created))
        })();
        match created {
            Ok(identity) => {
                reservations.push((path, file_name.clone(), device_path.clone(), identity));
            }
            Err(error) => {
                let error_code = io_error_code(&error);
                return Some(
                    AnalysisError::output(operation, "local_destination_unavailable")
                        .with_captured_output(captured_output)
                        .with_user_message(format!(
                            "pm path for {package_name} reported {}, whose file name {} cannot be written to a unique local destination ({}). No APK was pulled.",
                            display_device_path(device_path),
                            display_device_path(file_name),
                            error_code.as_deref().unwrap_or("unknown error"),
                        ))
                        .with_remediation(
                            "Review details.diagnostics and details.captured_output for the refused destination. Correct the output filesystem conflict before retrying; REA does not rename APKs.",
                        )
                        .with_diagnostics(crate::common::errors::object(serde_json::json!({
                            "package_name": package_name,
                            "device_path": device_path,
                            "file_name": file_name,
                            "error_code": error_code,
                        }))),
                );
            }
        }
    }
    for (path, file_name, device_path, identity) in &reservations {
        let released = (|| -> std::io::Result<()> {
            let current = fs::symlink_metadata(path)?;
            if !current.is_dir()
                || current.file_type().is_symlink()
                || directory_identity(&current) != *identity
            {
                return Err(std::io::Error::other(format!(
                    "The local filename reservation changed before release: {}",
                    path.display()
                )));
            }
            fs::remove_dir(path)
        })();
        if let Err(error) = released {
            let error_code = io_error_code(&error);
            return Some(
                AnalysisError::output(operation, "local_destination_unavailable")
                    .with_captured_output(captured_output)
                    .with_user_message(format!(
                        "Could not release the local filename reservation for {} ({}); no APK was pulled.",
                        display_device_path(device_path),
                        error_code.as_deref().unwrap_or("unknown error"),
                    ))
                    .with_remediation(
                        "Review details.diagnostics and details.captured_output for the refused destination. Correct the output filesystem conflict before retrying; REA does not rename APKs.",
                    )
                    .with_diagnostics(crate::common::errors::object(serde_json::json!({
                        "package_name": package_name,
                        "device_path": device_path,
                        "file_name": file_name,
                        "error_code": error_code,
                    }))),
            );
        }
    }
    None
}

fn io_error_code(error: &std::io::Error) -> Option<String> {
    files::io_code(error).map(str::to_owned)
}

/// `publishBugreport(source, directory)`: copy without replacing a caller file,
/// adding ` (N)` suffixes until an exclusive create succeeds.
pub fn publish_bugreport(source: &str, directory: &str) -> std::io::Result<String> {
    let source_path = Path::new(source);
    let file_name = source_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (stem, extension) = split_extension(&file_name);
    let mut suffix = 0u64;
    loop {
        let candidate_name = if suffix == 0 {
            file_name.clone()
        } else {
            format!("{stem} ({suffix}){extension}")
        };
        let destination = Path::new(directory).join(&candidate_name);
        match copy_file_exclusive(source_path, &destination) {
            Ok(()) => return Ok(destination.to_string_lossy().into_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                suffix += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

fn split_extension(file_name: &str) -> (String, String) {
    // Node path.extname: the extension is the substring from the last '.' that
    // is not the first character; otherwise "".
    match file_name.rfind('.') {
        Some(index) if index > 0 => (file_name[..index].to_owned(), file_name[index..].to_owned()),
        _ => (file_name.to_owned(), String::new()),
    }
}

fn copy_file_exclusive(source: &Path, destination: &Path) -> std::io::Result<()> {
    let mut input = fs::File::open(source)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut output = options.open(destination)?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
    }
    output.flush()?;
    Ok(())
}

/// A copied caller-input snapshot: private path, byte size and digest.
pub struct InputSnapshot {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// `snapshotAdbInput(sourcePath, root, ...)`: copy one caller file into a
/// private root, hashing the bytes adb will consume, and verify the source
/// stayed unchanged. The destination is made read-only after sync.
pub fn snapshot_adb_input(
    source_path: &Path,
    root: &Path,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<InputSnapshot, AnalysisError> {
    let (mut source, initial) =
        files::open_regular(source_path, true, cancellation).map_err(|error| {
            AnalysisError::output(
                operation,
                format!(
                    "The caller input could not be staged for adb: {}",
                    source_path.display()
                ),
            )
            .with_diagnostics(crate::common::errors::object(serde_json::json!({
                "stable_file_error": error.to_string(),
            })))
        })?;
    let file_name = source_path
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_default();
    let destination_path = root.join(&file_name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut destination = options.open(&destination_path).map_err(|error| {
        AnalysisError::output(
            operation,
            format!(
                "The caller input could not be staged for adb: {}",
                source_path.display()
            ),
        )
        .with_diagnostics(crate::common::errors::object(serde_json::json!({
            "io_error": error.to_string(),
        })))
    })?;

    let copy = (|| -> Result<InputSnapshot, AnalysisError> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut position: u64 = 0;
        while position < initial.size {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(operation));
            }
            let want = std::cmp::min(buffer.len() as u64, initial.size - position) as usize;
            let read = source
                .read(&mut buffer[..want])
                .map_err(|error| AnalysisError::output(operation, error.to_string()))?;
            if read == 0 {
                return Err(AnalysisError::artifact_changed(
                    operation,
                    source_path.display().to_string(),
                    "the file ended before its admitted size was copied",
                ));
            }
            destination
                .write_all(&buffer[..read])
                .map_err(|error| AnalysisError::output(operation, error.to_string()))?;
            hasher.update(&buffer[..read]);
            position += read as u64;
        }
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let opened = FileState::of(
            &source
                .metadata()
                .map_err(|error| AnalysisError::output(operation, error.to_string()))?,
        );
        let named = FileState::of(
            &fs::metadata(source_path)
                .map_err(|error| AnalysisError::output(operation, error.to_string()))?,
        );
        if !initial.same_regular(&opened) || !initial.same_regular(&named) {
            return Err(AnalysisError::artifact_changed(
                operation,
                source_path.display().to_string(),
                "the file changed while its private snapshot was copied",
            ));
        }
        destination
            .flush()
            .map_err(|error| AnalysisError::output(operation, error.to_string()))?;
        Ok(InputSnapshot {
            path: destination_path.to_string_lossy().into_owned(),
            bytes: position,
            sha256: format!("{:x}", hasher.finalize()),
        })
    })();

    drop(destination);
    drop(source);
    match copy {
        Ok(snapshot) => {
            let _ = files::make_read_only(&destination_path);
            Ok(snapshot)
        }
        Err(error) => {
            let _ = fs::remove_file(&destination_path);
            Err(error)
        }
    }
}
