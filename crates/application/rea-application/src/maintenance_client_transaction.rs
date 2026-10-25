//! Transactional filesystem owner for prepared client registrations.
//!
//! Configuration parsing and registration identity belong to
//! [`super::maintenance_clients`]. This module owns only the byte-level
//! transaction: preflight every target, create exclusive retained backups,
//! install prepared bytes, verify readback, and recover completed targets when
//! a later target fails.

use crate::maintenance_clients::{ClientConfigurationFormat, ClientRegistrationTarget};
use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_file;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedClientChange {
    pub target: ClientRegistrationTarget,
    pub operation: ClientMutationOperation,
    pub expected_sha256: Option<String>,
    pub original_bytes: Option<Vec<u8>>,
    pub replacement_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientMutationOperation {
    Configure,
    Remove,
}

impl PreparedClientChange {
    #[must_use]
    pub fn configure(
        target: ClientRegistrationTarget,
        expected_sha256: Option<String>,
        original_bytes: Option<Vec<u8>>,
        replacement_bytes: Vec<u8>,
    ) -> Self {
        Self {
            target,
            operation: ClientMutationOperation::Configure,
            expected_sha256,
            original_bytes,
            replacement_bytes: Some(replacement_bytes),
        }
    }

    #[must_use]
    pub fn remove(
        target: ClientRegistrationTarget,
        expected_sha256: Option<String>,
        original_bytes: Option<Vec<u8>>,
        replacement_bytes: Vec<u8>,
    ) -> Self {
        Self {
            target,
            operation: ClientMutationOperation::Remove,
            expected_sha256,
            original_bytes,
            replacement_bytes: Some(replacement_bytes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionItem {
    pub client_id: String,
    pub path: PathBuf,
    pub status: TransactionItemStatus,
    pub backup_path: Option<PathBuf>,
    pub recovery_path: Option<PathBuf>,
    pub detail: Option<String>,
    created_directories: Vec<PathBuf>,
    original_bytes: Option<Vec<u8>>,
    replacement_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionItemStatus {
    Applied,
    Skipped,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReport {
    pub items: Vec<TransactionItem>,
    pub primary_failure: Option<String>,
    pub cleanup_failures: Vec<String>,
}

/// Owns a stable-file lease that could not be closed during error recovery.
///
/// The owner stays attached to [`ClientTransactionError`] until a caller
/// retries cleanup successfully, so a failed cleanup never silently discards
/// the handle or the path it protects.
#[derive(Debug)]
pub enum StableReadOwner {
    #[cfg(unix)]
    Unix(stable_file::Lease<rea_host::fs::unix_file::UnixFiles>),
    #[cfg(windows)]
    Windows(stable_file::Lease<rea_host::fs::windows_file::WindowsFiles>),
}

impl StableReadOwner {
    fn retry_cleanup(&mut self) -> Result<(), String> {
        let result = match self {
            #[cfg(unix)]
            Self::Unix(owner) => owner.close(),
            #[cfg(windows)]
            Self::Windows(owner) => owner.close(),
        };
        result.map_err(|failure| failure.error.to_string())
    }

    fn retains_resource(&self) -> bool {
        match self {
            #[cfg(unix)]
            Self::Unix(owner) => owner.retains_resource(),
            #[cfg(windows)]
            Self::Windows(owner) => owner.retains_resource(),
        }
    }
}

#[derive(Debug)]
pub enum ClientTransactionError {
    InvalidPreparation(String),
    Preflight(String),
    Io {
        path: PathBuf,
        source: io::Error,
    },
    RetainedArtifact {
        error: Box<Self>,
        recovery_path: PathBuf,
    },
    Verification(String),
    StableRead {
        primary: Option<String>,
        completed: Option<Vec<u8>>,
        cleanup_failures: Vec<String>,
        retained: Option<StableReadOwner>,
    },
    ConcurrentReplacement {
        detail: String,
        recovery_path: PathBuf,
    },
    Committed {
        error: Box<Self>,
        item: Box<TransactionItem>,
    },
}

/// Read a target through the transaction owner's identity checks.
pub fn read_client_source(
    target: &ClientRegistrationTarget,
) -> Result<Option<Vec<u8>>, ClientTransactionError> {
    read_owned_file(&target.path)
}

/// Read a configuration path through the transaction owner's identity checks.
///
/// Inspection callers do not yet have a fully resolved registration target,
/// but they must share the same symlink and replacement checks as mutation.
pub fn read_client_source_path(path: &Path) -> Result<Option<Vec<u8>>, ClientTransactionError> {
    read_owned_file(path)
}

impl std::fmt::Display for ClientTransactionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPreparation(detail) => {
                write!(formatter, "invalid client preparation: {detail}")
            }
            Self::Preflight(detail) => {
                write!(formatter, "client transaction preflight failed: {detail}")
            }
            Self::Io { path, source } => write!(
                formatter,
                "client transaction I/O failed for {}: {source}",
                path.display()
            ),
            Self::RetainedArtifact {
                error,
                recovery_path,
            } => write!(
                formatter,
                "{error}; retained partial artifact at {}",
                recovery_path.display()
            ),
            Self::Verification(detail) => write!(
                formatter,
                "client transaction verification failed: {detail}"
            ),
            Self::StableRead {
                primary,
                completed,
                cleanup_failures,
                retained,
            } => write!(
                formatter,
                "stable client read failed (primary: {primary:?}, completed bytes: {}, cleanup failures: {}, retained owner: {})",
                completed.as_ref().map_or(0, Vec::len),
                cleanup_failures.len(),
                retained.is_some(),
            ),
            Self::ConcurrentReplacement {
                detail,
                recovery_path,
            } => write!(
                formatter,
                "client transaction rollback preserved a concurrent replacement at {}: {detail}",
                recovery_path.display()
            ),
            Self::Committed { error, .. } => write!(formatter, "{error}"),
        }
    }
}

impl ClientTransactionError {
    #[must_use]
    pub fn recovery_path(&self) -> Option<&Path> {
        match self {
            Self::ConcurrentReplacement { recovery_path, .. } => Some(recovery_path),
            Self::RetainedArtifact { recovery_path, .. } => Some(recovery_path),
            Self::Committed { error, .. } => error.recovery_path(),
            _ => None,
        }
    }

    /// Retry cleanup for a retained stable-file read owner. The owner remains
    /// attached to this error until the host confirms that its handle closed.
    pub fn retry_stable_read_cleanup(&mut self) -> Result<(), String> {
        let Self::StableRead { retained, .. } = self else {
            return Ok(());
        };
        let Some(owner) = retained.as_mut() else {
            return Ok(());
        };
        let result = owner.retry_cleanup();
        if !owner.retains_resource() {
            *retained = None;
        }
        result
    }
}

impl std::error::Error for ClientTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::RetainedArtifact { error, .. } => Some(error.as_ref()),
            Self::Committed { error, .. } => error.source(),
            _ => None,
        }
    }
}

/// Apply all prepared changes as one optimistic transaction.
///
/// Every target is read and validated before the first write. A failure during
/// commit triggers independent rollback attempts for completed targets. A
/// rollback never overwrites a concurrent replacement: it restores only when
/// the current bytes still match the bytes this transaction wrote.
pub fn apply_transaction(
    changes: &[PreparedClientChange],
    approved: bool,
) -> Result<TransactionReport, ClientTransactionError> {
    if changes.is_empty() {
        return Ok(TransactionReport {
            items: Vec::new(),
            primary_failure: None,
            cleanup_failures: Vec::new(),
        });
    }
    if !approved {
        return Err(ClientTransactionError::Preflight(
            "filesystem changes require explicit approval".to_owned(),
        ));
    }

    preflight(changes)?;

    let mut completed = Vec::with_capacity(changes.len());
    for change in changes {
        match apply_one(change) {
            Ok(item) => completed.push(item),
            Err(ClientTransactionError::Committed { error, item }) => {
                completed.push(*item);
                let mut cleanup_failures = Vec::new();
                for completed_change in &mut completed {
                    if let Err(error) = rollback_one(completed_change) {
                        if let Some(path) = error.recovery_path() {
                            completed_change.recovery_path = Some(path.to_owned());
                        }
                        completed_change.status = TransactionItemStatus::Failed;
                        cleanup_failures.push(error.to_string());
                    } else {
                        completed_change.status = TransactionItemStatus::RolledBack;
                    }
                }
                return Ok(TransactionReport {
                    items: completed,
                    primary_failure: Some(error.to_string()),
                    cleanup_failures,
                });
            }
            Err(primary) => {
                let mut cleanup_failures = Vec::new();
                for completed_change in &mut completed {
                    if let Err(error) = rollback_one(completed_change) {
                        if let Some(path) = error.recovery_path() {
                            completed_change.recovery_path = Some(path.to_owned());
                        }
                        completed_change.status = TransactionItemStatus::Failed;
                        cleanup_failures.push(error.to_string());
                    } else {
                        completed_change.status = TransactionItemStatus::RolledBack;
                    }
                }
                return Ok(TransactionReport {
                    items: completed,
                    primary_failure: Some(primary.to_string()),
                    cleanup_failures,
                });
            }
        }
    }

    Ok(TransactionReport {
        items: completed,
        primary_failure: None,
        cleanup_failures: Vec::new(),
    })
}

fn preflight(changes: &[PreparedClientChange]) -> Result<(), ClientTransactionError> {
    let mut paths = std::collections::BTreeSet::new();
    for change in changes {
        if !paths.insert(change.target.path.clone()) {
            return Err(ClientTransactionError::Preflight(format!(
                "duplicate target {}",
                change.target.path.display()
            )));
        }
        if change.target.format == ClientConfigurationFormat::Unsupported {
            return Err(ClientTransactionError::Preflight(format!(
                "unsupported configuration format for {}",
                change.target.id
            )));
        }
        if change.replacement_bytes.is_none() {
            return Err(ClientTransactionError::InvalidPreparation(format!(
                "missing replacement bytes for {}",
                change.target.id
            )));
        }
        let current = read_owned_file(&change.target.path)?;
        let current_digest = current.as_deref().map(sha256_hex);
        if current_digest != change.expected_sha256 {
            return Err(ClientTransactionError::Preflight(format!(
                "source changed for {} (expected {:?}, found {:?})",
                change.target.id, change.expected_sha256, current_digest
            )));
        }
        if current != change.original_bytes {
            return Err(ClientTransactionError::Preflight(format!(
                "prepared source bytes do not match {}",
                change.target.id
            )));
        }
    }
    Ok(())
}

fn apply_one(change: &PreparedClientChange) -> Result<TransactionItem, ClientTransactionError> {
    let current = validate_apply_source(change)?;
    let replacement = prepared_replacement(change)?;
    let backup_path = current
        .as_deref()
        .map(|bytes| create_retained_backup(&change.target.path, bytes))
        .transpose()?;
    let created_directories = publish_replacement(change, replacement, backup_path.as_deref())?;

    let item = TransactionItem {
        client_id: change.target.id.clone(),
        path: change.target.path.clone(),
        status: TransactionItemStatus::Applied,
        backup_path,
        recovery_path: None,
        detail: None,
        created_directories,
        original_bytes: change.original_bytes.clone(),
        replacement_bytes: replacement.to_vec(),
    };
    verify_published_item(change, item)
}

fn validate_apply_source(
    change: &PreparedClientChange,
) -> Result<Option<Vec<u8>>, ClientTransactionError> {
    let current = read_owned_file(&change.target.path)?;
    if current.as_deref().map(sha256_hex) != change.expected_sha256 {
        return Err(ClientTransactionError::Preflight(format!(
            "source changed before applying {}",
            change.target.id
        )));
    }
    Ok(current)
}

fn prepared_replacement(change: &PreparedClientChange) -> Result<&[u8], ClientTransactionError> {
    change.replacement_bytes.as_deref().ok_or_else(|| {
        ClientTransactionError::InvalidPreparation(format!(
            "missing replacement bytes for {}",
            change.target.id
        ))
    })
}

fn publish_replacement(
    change: &PreparedClientChange,
    replacement: &[u8],
    backup_path: Option<&Path>,
) -> Result<Vec<PathBuf>, ClientTransactionError> {
    let (temporary_path, created_directories) =
        write_exclusive_temporary(&change.target.path, replacement)
            .map_err(|error| retain_backup_on_failure(error, backup_path))?;

    let latest = match read_owned_file(&change.target.path) {
        Ok(latest) => latest,
        Err(error) => {
            return Err(retain_backup_after_temporary_failure(
                error,
                &temporary_path,
                &created_directories,
                backup_path,
            ));
        }
    };
    if latest.as_deref().map(sha256_hex) != change.expected_sha256 {
        let error = ClientTransactionError::Preflight(format!(
            "source changed before publishing {}",
            change.target.id
        ));
        return Err(retain_backup_after_temporary_failure(
            error,
            &temporary_path,
            &created_directories,
            backup_path,
        ));
    }

    if let Err(source) = fs::rename(&temporary_path, &change.target.path) {
        let error = ClientTransactionError::Io {
            path: change.target.path.clone(),
            source,
        };
        return Err(retain_backup_after_temporary_failure(
            error,
            &temporary_path,
            &created_directories,
            backup_path,
        ));
    }

    Ok(created_directories)
}

fn retain_backup_after_temporary_failure(
    error: ClientTransactionError,
    temporary_path: &Path,
    created_directories: &[PathBuf],
    backup_path: Option<&Path>,
) -> ClientTransactionError {
    let cleanup = fs::remove_file(temporary_path).err();
    let error = append_temporary_cleanup(error, temporary_path, cleanup);
    let error = append_directory_cleanup(error, created_directories);
    retain_backup_on_failure(error, backup_path)
}

fn verify_published_item(
    change: &PreparedClientChange,
    item: TransactionItem,
) -> Result<TransactionItem, ClientTransactionError> {
    let readback = match read_owned_file(&change.target.path) {
        Ok(readback) => readback,
        Err(error) => {
            return Err(ClientTransactionError::Committed {
                error: Box::new(error),
                item: Box::new(item),
            });
        }
    };
    if readback.as_deref() != change.replacement_bytes.as_deref() {
        return Err(ClientTransactionError::Committed {
            error: Box::new(ClientTransactionError::Verification(format!(
                "readback differs from prepared bytes for {}",
                change.target.id
            ))),
            item: Box::new(item),
        });
    }
    Ok(item)
}

fn retain_backup_on_failure(
    error: ClientTransactionError,
    backup_path: Option<&Path>,
) -> ClientTransactionError {
    let Some(backup_path) = backup_path else {
        return error;
    };
    ClientTransactionError::RetainedArtifact {
        error: Box::new(error),
        recovery_path: backup_path.to_owned(),
    }
}

fn append_temporary_cleanup(
    error: ClientTransactionError,
    temporary_path: &Path,
    cleanup: Option<io::Error>,
) -> ClientTransactionError {
    let Some(cleanup_error) = cleanup else {
        return error;
    };
    ClientTransactionError::Verification(format!(
        "{error}; temporary cleanup failed for {}: {cleanup_error}",
        temporary_path.display()
    ))
}

fn append_directory_cleanup(
    error: ClientTransactionError,
    directories: &[PathBuf],
) -> ClientTransactionError {
    match remove_empty_directories(directories) {
        Ok(()) => error,
        Err(cleanup_error) => ClientTransactionError::Verification(format!(
            "{error}; directory cleanup failed: {cleanup_error}"
        )),
    }
}

fn rollback_one(item: &TransactionItem) -> Result<(), ClientTransactionError> {
    let current = read_owned_file(&item.path)?.ok_or_else(|| {
        ClientTransactionError::Verification(format!(
            "installed file disappeared for {}",
            item.client_id
        ))
    })?;
    if current.as_slice() != item.replacement_bytes.as_slice() {
        let recovery = create_retained_backup(&item.path, &current)?;
        return Err(ClientTransactionError::ConcurrentReplacement {
            detail: format!("concurrent replacement for {}", item.client_id),
            recovery_path: recovery,
        });
    }
    match &item.original_bytes {
        Some(original) => {
            let (temporary_path, created_directories) =
                write_exclusive_temporary(&item.path, original)?;
            if let Err(source) = fs::rename(&temporary_path, &item.path) {
                let cleanup = fs::remove_file(&temporary_path).err();
                let error = append_temporary_cleanup(
                    ClientTransactionError::Io {
                        path: item.path.clone(),
                        source,
                    },
                    &temporary_path,
                    cleanup,
                );
                return Err(append_directory_cleanup(error, &created_directories));
            }
        }
        None => {
            fs::remove_file(&item.path).map_err(|source| ClientTransactionError::Io {
                path: item.path.clone(),
                source,
            })?;
        }
    }
    let restored = read_owned_file(&item.path)?;
    if restored != item.original_bytes {
        return Err(ClientTransactionError::Verification(format!(
            "rollback readback differs for {}",
            item.client_id
        )));
    }
    if let Some(backup_path) = &item.backup_path {
        if read_owned_file(backup_path)?.is_none() {
            return Err(ClientTransactionError::Verification(format!(
                "backup disappeared for {}",
                item.client_id
            )));
        }
    }
    remove_created_directories(item)?;
    Ok(())
}

fn remove_created_directories(item: &TransactionItem) -> Result<(), ClientTransactionError> {
    remove_empty_directories(&item.created_directories)
}

fn remove_empty_directories(directories: &[PathBuf]) -> Result<(), ClientTransactionError> {
    for directory in directories.iter().rev() {
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {}
            Err(source) => {
                return Err(ClientTransactionError::Io {
                    path: directory.clone(),
                    source,
                });
            }
        }
    }
    Ok(())
}

fn read_owned_file(path: &Path) -> Result<Option<Vec<u8>>, ClientTransactionError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ClientTransactionError::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(ClientTransactionError::Preflight(format!(
            "refusing symlink target {}",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(ClientTransactionError::Preflight(format!(
            "target is not a regular file: {}",
            path.display()
        )));
    }
    const MAX_CLIENT_CONFIGURATION_BYTES: usize = 64 * 1024 * 1024;
    let bytes = read_stable_file(path, MAX_CLIENT_CONFIGURATION_BYTES)?;
    Ok(Some(bytes))
}

#[cfg(unix)]
fn read_stable_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ClientTransactionError> {
    let snapshot = stable_file::read(
        std::sync::Arc::new(rea_host::fs::unix_file::UnixFiles),
        path,
        maximum,
        &Cancellation::default(),
    )
    .map_err(stable_read_error)?;
    Ok(snapshot.bytes)
}

#[cfg(unix)]
fn stable_read_error(
    mut failure: Box<stable_file::ReadFailure<rea_host::fs::unix_file::UnixFiles>>,
) -> ClientTransactionError {
    retry_stable_read_cleanup(&mut failure);
    ClientTransactionError::StableRead {
        primary: failure.primary.map(|issue| format!("{issue:?}")),
        completed: failure.completed.map(|snapshot| snapshot.bytes),
        cleanup_failures: failure
            .cleanup_failures
            .iter()
            .map(|cleanup| cleanup.error.to_string())
            .collect(),
        retained: failure.retained.map(StableReadOwner::Unix),
    }
}

#[cfg(windows)]
fn read_stable_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ClientTransactionError> {
    let snapshot = stable_file::read(
        std::sync::Arc::new(rea_host::fs::windows_file::WindowsFiles),
        path,
        maximum,
        &Cancellation::default(),
    )
    .map_err(stable_read_error)?;
    Ok(snapshot.bytes)
}

#[cfg(windows)]
fn stable_read_error(
    mut failure: Box<stable_file::ReadFailure<rea_host::fs::windows_file::WindowsFiles>>,
) -> ClientTransactionError {
    retry_stable_read_cleanup(&mut failure);
    ClientTransactionError::StableRead {
        primary: failure.primary.map(|issue| format!("{issue:?}")),
        completed: failure.completed.map(|snapshot| snapshot.bytes),
        cleanup_failures: failure
            .cleanup_failures
            .iter()
            .map(|cleanup| cleanup.error.to_string())
            .collect(),
        retained: failure.retained.map(StableReadOwner::Windows),
    }
}

fn retry_stable_read_cleanup<F: stable_file::FileAccess>(
    failure: &mut stable_file::ReadFailure<F>,
) {
    for _attempt in 0..3 {
        if failure.retained.is_none() {
            break;
        }
        if failure.retry_cleanup().is_ok() {
            break;
        }
    }
}

fn write_exclusive_temporary(
    path: &Path,
    bytes: &[u8],
) -> Result<(PathBuf, Vec<PathBuf>), ClientTransactionError> {
    let parent = path.parent().ok_or_else(|| {
        ClientTransactionError::Preflight(format!("target has no parent: {}", path.display()))
    })?;
    let created_directories = create_missing_directories(parent)?;
    for attempt in 0..32_u32 {
        let temporary = parent.join(format!(
            ".{}.rea-tmp-{}-{attempt}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            process_id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(mut file) => {
                if let Err(source) = file.write_all(bytes) {
                    let cleanup = fs::remove_file(&temporary).err();
                    let error = append_temporary_cleanup(
                        ClientTransactionError::Io {
                            path: temporary.clone(),
                            source,
                        },
                        &temporary,
                        cleanup,
                    );
                    return Err(append_directory_cleanup(error, &created_directories));
                }
                if let Err(source) = file.sync_all() {
                    let cleanup = fs::remove_file(&temporary).err();
                    let error = append_temporary_cleanup(
                        ClientTransactionError::Io {
                            path: temporary.clone(),
                            source,
                        },
                        &temporary,
                        cleanup,
                    );
                    return Err(append_directory_cleanup(error, &created_directories));
                }
                return Ok((temporary, created_directories));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                let error = ClientTransactionError::Io {
                    path: temporary,
                    source,
                };
                return Err(append_directory_cleanup(error, &created_directories));
            }
        }
    }
    let error = ClientTransactionError::Preflight(format!(
        "unable to allocate exclusive temporary for {}",
        path.display()
    ));
    Err(append_directory_cleanup(error, &created_directories))
}

fn create_missing_directories(path: &Path) -> Result<Vec<PathBuf>, ClientTransactionError> {
    let mut missing = Vec::new();
    let mut current = path;
    while !current.exists() {
        missing.push(current.to_owned());
        current = current.parent().ok_or_else(|| {
            ClientTransactionError::Preflight(format!(
                "target parent has no existing ancestor: {}",
                path.display()
            ))
        })?;
    }
    let metadata = fs::symlink_metadata(current).map_err(|source| ClientTransactionError::Io {
        path: current.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ClientTransactionError::Preflight(format!(
            "target parent is not a real directory: {}",
            current.display()
        )));
    }
    let mut created = Vec::new();
    for directory in missing.iter().rev() {
        if let Err(source) = fs::create_dir(directory) {
            let cleanup = remove_empty_directories(&created).err();
            let error = ClientTransactionError::Io {
                path: directory.clone(),
                source,
            };
            return Err(match cleanup {
                Some(cleanup_error) => ClientTransactionError::Verification(format!(
                    "{error}; directory cleanup failed: {cleanup_error}"
                )),
                None => error,
            });
        }
        created.push(directory.clone());
    }
    created.reverse();
    Ok(created)
}

fn create_retained_backup(path: &Path, bytes: &[u8]) -> Result<PathBuf, ClientTransactionError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..32_u32 {
        let backup = path.with_extension(format!("rea-backup-{stamp}-{attempt}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup)
        {
            Ok(mut file) => {
                if let Err(source) = file.write_all(bytes) {
                    return Err(retained_backup_failure(&backup, source));
                }
                if let Err(source) = file.sync_all() {
                    return Err(retained_backup_failure(&backup, source));
                }
                return Ok(backup);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ClientTransactionError::Io {
                    path: backup,
                    source,
                });
            }
        }
    }
    Err(ClientTransactionError::Preflight(format!(
        "unable to allocate retained backup for {}",
        path.display()
    )))
}

fn retained_backup_failure(path: &Path, source: io::Error) -> ClientTransactionError {
    ClientTransactionError::RetainedArtifact {
        error: Box::new(ClientTransactionError::Io {
            path: path.to_owned(),
            source,
        }),
        recovery_path: path.to_owned(),
    }
}

fn process_id() -> u32 {
    std::process::id()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn target(path: &Path) -> ClientRegistrationTarget {
        ClientRegistrationTarget {
            id: "test".to_owned(),
            display_name: "Test".to_owned(),
            path: path.to_owned(),
            evidence_paths: vec![path.to_owned()],
            marker_path: path.to_owned(),
            format: ClientConfigurationFormat::Json,
            server_key: "mcpServers",
            config_path_error: None,
            quit_before_setup: false,
            manual_registration: false,
        }
    }

    #[test]
    fn applies_and_retains_backup() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("config.json");
        fs::write(&path, b"old").expect("write");
        let change = PreparedClientChange::configure(
            target(&path),
            Some(sha256_hex(b"old")),
            Some(b"old".to_vec()),
            b"new".to_vec(),
        );
        let report = apply_transaction(&[change], true).expect("transaction");
        assert_eq!(report.primary_failure, None);
        assert_eq!(fs::read(&path).expect("read"), b"new");
        assert_eq!(report.items.len(), 1);
        assert!(
            report.items[0]
                .backup_path
                .as_ref()
                .is_some_and(|backup| backup.exists())
        );
    }

    #[test]
    fn preflight_rejects_changed_source_without_writing() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("config.json");
        fs::write(&path, b"changed").expect("write");
        let change = PreparedClientChange::configure(
            target(&path),
            Some(sha256_hex(b"old")),
            Some(b"old".to_vec()),
            b"new".to_vec(),
        );
        assert!(matches!(
            apply_transaction(&[change], true),
            Err(ClientTransactionError::Preflight(_))
        ));
        assert_eq!(fs::read(&path).expect("read"), b"changed");
    }

    #[test]
    fn refuses_symlink_targets() {
        let directory = tempdir().expect("tempdir");
        let real = directory.path().join("real.json");
        let link = directory.path().join("link.json");
        fs::write(&real, b"old").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real, &link).expect("symlink");
        let change = PreparedClientChange::configure(
            target(&link),
            Some(sha256_hex(b"old")),
            Some(b"old".to_vec()),
            b"new".to_vec(),
        );
        assert!(matches!(
            apply_transaction(&[change], true),
            Err(ClientTransactionError::Preflight(_))
        ));
    }

    #[test]
    fn rolls_back_completed_target_when_later_target_cannot_be_written() {
        let directory = tempdir().expect("tempdir");
        let first_path = directory.path().join("conflict");
        let second_path = first_path.join("second.json");

        let first =
            PreparedClientChange::configure(target(&first_path), None, None, b"first-new".to_vec());

        let second = PreparedClientChange::configure(
            target(&second_path),
            None,
            None,
            b"second-new".to_vec(),
        );
        let report = apply_transaction(&[first, second], true).expect("report");

        assert!(report.primary_failure.is_some());
        assert!(report.cleanup_failures.is_empty());
        assert_eq!(report.items[0].status, TransactionItemStatus::RolledBack);
        assert!(!first_path.exists());
    }
}
