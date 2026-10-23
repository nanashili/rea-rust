//! Atomic local publication with explicit ownership through failed cleanup.
//! Cancellation can prevent publication, but cannot revoke a committed file or
//! abandon final cleanup. No destructor recursively deletes staging paths.
use crate::{
    fs::stable_file::{CloseOutcome, FileAccess},
    fs::unix_file::UnixFiles,
};
use rea_core::cancellation::Cancellation;
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, CWD, FileType, Mode, OFlags, Stat},
};
use std::os::unix::ffi::OsStrExt;
use std::{
    error::Error,
    fmt,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum WriteIssue {
    Exists,
    NotFile,
    Cancelled,
    Io(io::Error),
    Encoding(Box<dyn Error + Send + Sync>),
}
impl fmt::Display for WriteIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => f.write_str("destination already exists"),
            Self::NotFile => f.write_str("destination is not a regular file"),
            Self::Cancelled => f.write_str("publication cancelled"),
            Self::Io(error) => error.fmt(f),
            Self::Encoding(error) => error.fmt(f),
        }
    }
}
impl Error for WriteIssue {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Encoding(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Published {
    pub bytes: u64,
}

/// A successful outcome here means publication committed despite cleanup failure.
#[derive(Debug)]
pub struct WriteFailure {
    pub outcome: Result<Published, WriteIssue>,
    pub cleanup: Option<io::Error>,
    pub retained: Option<Box<StagedOutput>>,
    /// Diagnostic identity survives even when a failed close consumed its FD.
    pub staging_directory: Option<PathBuf>,
}
impl WriteFailure {
    fn early(issue: WriteIssue) -> Self {
        Self {
            outcome: Err(issue),
            cleanup: None,
            retained: None,
            staging_directory: None,
        }
    }
    /// Retry the exact retained owner, never reconstructed descriptor numbers.
    pub fn retry_cleanup(&mut self) -> io::Result<()> {
        if let Some(owner) = &mut self.retained {
            owner.cleanup()?;
        }
        self.retained = None;
        self.cleanup = None;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u128,
}
fn identity(stat: &Stat) -> Identity {
    Identity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u128,
    }
}
fn other(message: &str) -> io::Error {
    io::Error::other(message)
}
fn active(cancellation: &Cancellation) -> Result<(), WriteIssue> {
    if cancellation.reason().is_some() {
        Err(WriteIssue::Cancelled)
    } else {
        Ok(())
    }
}

/// The original directory descriptor pins relative staged-file operations.
#[derive(Debug)]
pub struct StagedOutput {
    directory: PathBuf,
    directory_id: Option<Identity>,
    directory_fd: Option<OwnedFd>,
    file: Option<OwnedFd>,
    file_id: Option<Identity>,
    file_created: bool,
    file_removed: bool,
    renamed: bool,
    directory_removed: bool,
    destination: PathBuf,
    overwrite: bool,
}
impl StagedOutput {
    fn prepare(
        destination: &Path,
        overwrite: bool,
        cancellation: &Cancellation,
    ) -> Result<Self, WriteFailure> {
        active(cancellation).map_err(WriteFailure::early)?;
        if destination.as_os_str().as_bytes().ends_with(b"/")
            || destination.as_os_str().as_bytes().ends_with(b"/.")
        {
            return Err(WriteFailure::early(WriteIssue::NotFile));
        }
        let parent = destination
            .parent()
            .ok_or_else(|| WriteFailure::early(WriteIssue::NotFile))?;
        let parent =
            std::fs::canonicalize(parent).map_err(|e| WriteFailure::early(WriteIssue::Io(e)))?;
        // Match realpath(dirname(requested)) followed by resolve(parent, basename).
        let destination = match destination.file_name() {
            Some(name) => parent.join(name),
            None if destination.components().next_back()
                == Some(std::path::Component::ParentDir) =>
            {
                parent.parent().unwrap_or(&parent).to_owned()
            }
            None => return Err(WriteFailure::early(WriteIssue::NotFile)),
        };
        match std::fs::symlink_metadata(&destination) {
            Ok(_) if !overwrite => return Err(WriteFailure::early(WriteIssue::Exists)),
            Ok(metadata) if !metadata.is_file() || metadata.is_symlink() => {
                return Err(WriteFailure::early(WriteIssue::NotFile));
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(WriteFailure::early(WriteIssue::Io(error)));
            }
            _ => {}
        }
        active(cancellation).map_err(WriteFailure::early)?;
        let directory = tempfile::Builder::new()
            .prefix(".rea-write-")
            .tempdir_in(parent)
            .map_err(|e| WriteFailure::early(WriteIssue::Io(e)))?
            .keep();
        let mut owner = Self {
            directory,
            directory_id: None,
            directory_fd: None,
            file: None,
            file_id: None,
            file_created: false,
            file_removed: false,
            renamed: false,
            directory_removed: false,
            destination,
            overwrite,
        };
        let initialized = (|| -> io::Result<()> {
            let stat = fs::lstat(&owner.directory)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                return Err(other("staging directory identity unavailable"));
            }
            owner.directory_id = Some(identity(&stat));
            let fd = fs::open(
                &owner.directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            owner.directory_fd = Some(fd);
            let opened = fs::fstat(owner.dir()?)?;
            if Some(identity(&opened)) != owner.directory_id {
                return Err(other("staging directory changed during admission"));
            }
            owner.file = Some(fs::openat(
                owner.dir()?,
                "content",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            owner.file_created = true;
            Ok(())
        })();
        match initialized {
            Ok(()) => Ok(owner),
            Err(error) => {
                let cleanup = owner.cleanup().err();
                let staging_directory = Some(owner.directory.clone());
                let retained = if cleanup.is_some() {
                    owner.retain_if_owned()
                } else {
                    None
                };
                Err(WriteFailure {
                    staging_directory,
                    outcome: Err(WriteIssue::Io(error)),
                    cleanup,
                    retained,
                })
            }
        }
    }
    fn dir(&self) -> io::Result<&OwnedFd> {
        let fd = self
            .directory_fd
            .as_ref()
            .ok_or_else(|| other("staging directory descriptor unavailable"))?;
        let stat = fs::fstat(fd)?;
        if self.directory_id.is_none()
            || Some(identity(&stat)) != self.directory_id
            || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        {
            return Err(other("staging descriptor ownership unresolved"));
        }
        Ok(fd)
    }
    fn verify_directory(&self) -> io::Result<()> {
        let stat = fs::lstat(&self.directory)?;
        if self.directory_id.is_none()
            || Some(identity(&stat)) != self.directory_id
            || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        {
            return Err(other("staging directory ownership unresolved"));
        }
        Ok(())
    }
    fn close_file(&mut self) -> io::Result<()> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        // Observe after the final write: FAT-family files may acquire an ID on
        // their first allocation. Failed observation must not authorize unlink.
        let observed = fs::fstat(&file).map(|stat| identity(&stat));
        self.file_id = observed.as_ref().ok().copied();
        let closed = close(file, &mut self.file);
        match (observed, closed) {
            (Err(observation), Err(release)) => Err(other(&format!(
                "Staged identity failed: {observation}; descriptor release failed: {release}"
            ))),
            (Err(error), _) => Err(error.into()),
            (_, result) => result,
        }
    }
    fn ready(&self) -> io::Result<()> {
        self.verify_directory()?;
        let stat = fs::statat(self.dir()?, "content", AtFlags::SYMLINK_NOFOLLOW)?;
        if self.file_id.is_none()
            || Some(identity(&stat)) != self.file_id
            || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        {
            return Err(other("staged file ownership unresolved"));
        }
        Ok(())
    }
    fn write<E: Error + Send + Sync + 'static>(
        &mut self,
        cancellation: &Cancellation,
        encode: impl FnOnce(&mut dyn Write) -> Result<(), E>,
    ) -> Result<u64, WriteIssue> {
        active(cancellation)?;
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| WriteIssue::Io(other("staged file is not open")))?;
        let mut writer = StagedWriter {
            file,
            cancellation,
            bytes: 0,
            failure: None,
        };
        let mut buffered = io::BufWriter::with_capacity(64 * 1024, &mut writer);
        let encoded = encode(&mut buffered);
        let flushed = if encoded.is_ok() {
            buffered.flush()
        } else {
            Ok(())
        };
        // Do not let BufWriter's destructor perform ignored writes after an
        // encoding failure or cancellation. Pending bytes are intentionally lost.
        let _ = buffered.into_parts();
        if let Some(issue) = writer.failure.take() {
            return Err(issue);
        }
        encoded.map_err(|error| WriteIssue::Encoding(Box::new(error)))?;
        flushed.map_err(WriteIssue::Io)?;
        active(cancellation)?;
        loop {
            match fs::fsync(file) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => active(cancellation)?,
                Err(error) => return Err(WriteIssue::Io(error.into())),
            }
        }
        Ok(writer.bytes)
    }
    fn publish(
        &mut self,
        bytes: u64,
        cancellation: &Cancellation,
    ) -> Result<Published, WriteIssue> {
        self.close_file().map_err(WriteIssue::Io)?;
        active(cancellation)?;
        self.ready().map_err(WriteIssue::Io)?;
        active(cancellation)?;
        if self.overwrite {
            fs::renameat(
                self.dir().map_err(WriteIssue::Io)?,
                "content",
                CWD,
                &self.destination,
            )
            .map_err(|e| WriteIssue::Io(e.into()))?;
            self.renamed = true;
        } else {
            fs::linkat(
                self.dir().map_err(WriteIssue::Io)?,
                "content",
                CWD,
                &self.destination,
                AtFlags::empty(),
            )
            .map_err(|e| {
                if e == rustix::io::Errno::EXIST {
                    WriteIssue::Exists
                } else {
                    WriteIssue::Io(e.into())
                }
            })?;
        }
        // Publication has won. Later cancellation must not erase this receipt.
        Ok(Published { bytes })
    }
    /// Cancellation is intentionally not an argument to final cleanup.
    pub fn cleanup(&mut self) -> io::Result<()> {
        self.close_file()?;
        if !self.directory_removed {
            self.verify_directory()?;
            if self.file_created {
                match fs::statat(self.dir()?, "content", AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => {
                        if self.file_id.is_none()
                            || Some(identity(&stat)) != self.file_id
                            || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                        {
                            return Err(other("staged file identity changed; refusing removal"));
                        }
                        fs::unlinkat(self.dir()?, "content", AtFlags::empty())?;
                        self.file_removed = true;
                    }
                    Err(rustix::io::Errno::NOENT)
                        if !self.file_created || self.file_removed || self.renamed => {}
                    Err(error) => return Err(error.into()),
                }
            }
            // rmdir refuses unexpected entries. Never recursively delete them.
            self.verify_directory()?;
            std::fs::remove_dir(&self.directory)?;
            self.directory_removed = true;
        }
        if let Some(fd) = self.directory_fd.take() {
            close(fd, &mut self.directory_fd)?;
        }
        Ok(())
    }
    fn finish(mut self, outcome: Result<Published, WriteIssue>) -> Result<Published, WriteFailure> {
        let cleanup = self.cleanup().err();
        if cleanup.is_none() {
            return outcome.map_err(WriteFailure::early);
        }
        let staging_directory = Some(self.directory.clone());
        let retained = self.retain_if_owned();
        Err(WriteFailure {
            outcome,
            cleanup,
            retained,
            staging_directory,
        })
    }
    fn retain_if_owned(self) -> Option<Box<Self>> {
        if !self.directory_removed || self.directory_fd.is_some() || self.file.is_some() {
            Some(Box::new(self))
        } else {
            None
        }
    }
}
fn close(fd: OwnedFd, retained: &mut Option<OwnedFd>) -> io::Result<()> {
    match UnixFiles.close(fd) {
        CloseOutcome::Released => Ok(()),
        CloseOutcome::ReleasedWithError(e) => Err(e.source),
        CloseOutcome::Retained { handle, error } => {
            *retained = Some(handle);
            Err(error.source)
        }
    }
}
struct StagedWriter<'a> {
    file: &'a OwnedFd,
    cancellation: &'a Cancellation,
    bytes: u64,
    failure: Option<WriteIssue>,
}
impl Write for StagedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() {
            return Err(other("staged output already failed"));
        }
        if self.cancellation.reason().is_some() {
            self.failure = Some(WriteIssue::Cancelled);
            return Err(other("publication cancelled"));
        }
        loop {
            match rustix::io::write(self.file, bytes) {
                Ok(count) => {
                    let Some(total) = self.bytes.checked_add(count as u64) else {
                        self.failure = Some(WriteIssue::Io(other("output byte count overflow")));
                        return Err(other("output byte count overflow"));
                    };
                    self.bytes = total;
                    return Ok(count);
                }
                Err(rustix::io::Errno::INTR) => {
                    if self.cancellation.reason().is_some() {
                        self.failure = Some(WriteIssue::Cancelled);
                        return Err(other("publication cancelled"));
                    }
                }
                Err(error) => {
                    self.failure = Some(WriteIssue::Io(error.into()));
                    return Err(error.into());
                }
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Publish encoded bytes atomically. On failure, callers must keep any retained
/// owner and retry its cleanup before abandoning the owning application scope.
pub fn publish<E: Error + Send + Sync + 'static>(
    destination: &Path,
    overwrite: bool,
    cancellation: &Cancellation,
    encode: impl FnOnce(&mut dyn Write) -> Result<(), E>,
) -> Result<Published, WriteFailure> {
    let mut owner = StagedOutput::prepare(destination, overwrite, cancellation)?;
    let outcome = owner
        .write(cancellation, encode)
        .and_then(|bytes| owner.publish(bytes, cancellation));
    owner.finish(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn no_replace_is_atomic_and_explicit_overwrite_publishes_complete_bytes() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("evidence.json");
        let cancellation = Cancellation::default();
        let mut owner = StagedOutput::prepare(&destination, false, &cancellation).unwrap();
        let bytes = owner
            .write(&cancellation, |out| out.write_all(b"candidate"))
            .unwrap();
        std::fs::write(&destination, b"competitor").unwrap();
        let outcome = owner.publish(bytes, &cancellation);
        let failure = owner.finish(outcome).unwrap_err();
        assert!(matches!(failure.outcome, Err(WriteIssue::Exists)));
        assert!(failure.retained.is_none());
        assert_eq!(std::fs::read(&destination).unwrap(), b"competitor");
        let result = publish(&destination, true, &cancellation, |out| {
            out.write_all("complete 😀".as_bytes())
        })
        .unwrap();
        assert_eq!(result.bytes, 13);
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            "complete 😀".as_bytes()
        );
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn symlink_selection_never_mutates_its_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let link = root.path().join("link");
        std::fs::write(&target, b"original").unwrap();
        symlink(&target, &link).unwrap();
        for overwrite in [false, true] {
            let failure = publish(&link, overwrite, &Cancellation::default(), |out| {
                out.write_all(b"replacement")
            })
            .unwrap_err();
            assert!(matches!(
                (&failure.outcome, overwrite),
                (Err(WriteIssue::Exists), false) | (Err(WriteIssue::NotFile), true)
            ));
            assert!(failure.retained.is_none());
        }
        assert_eq!(std::fs::read(target).unwrap(), b"original");
        for destination in [root.path().to_owned(), root.path().join("target/..")] {
            for overwrite in [false, true] {
                let failure = publish(&destination, overwrite, &Cancellation::default(), |out| {
                    out.write_all(b"replacement")
                })
                .unwrap_err();
                assert!(matches!(
                    (&failure.outcome, overwrite),
                    (Err(WriteIssue::Exists), false) | (Err(WriteIssue::NotFile), true)
                ));
                assert!(failure.retained.is_none());
            }
        }
        let failure = publish(
            &root.path().join("."),
            false,
            &Cancellation::default(),
            |out| out.write_all(b"replacement"),
        )
        .unwrap_err();
        assert!(matches!(failure.outcome, Err(WriteIssue::NotFile)));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn cancellation_is_not_swallowed_by_an_encoder_and_leaves_no_publication() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("output");
        let cancellation = Cancellation::default();
        cancellation.cancel("before staging");
        let failure = publish(&destination, false, &cancellation, |_| -> io::Result<()> {
            panic!("encoder must not run")
        })
        .unwrap_err();
        assert!(matches!(failure.outcome, Err(WriteIssue::Cancelled)));
        let cancellation = Cancellation::default();
        let failure = publish(
            &destination,
            false,
            &cancellation,
            |out| -> io::Result<()> {
                out.write_all(&vec![1; 128 * 1024])?;
                cancellation.cancel("during encoding");
                let _ = out.write_all(&vec![2; 128 * 1024]);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(failure.outcome, Err(WriteIssue::Cancelled)));
        assert!(failure.retained.is_none());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn encoding_failure_is_not_replaced_by_a_later_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let cancellation = Cancellation::default();
        let failure = publish(
            &root.path().join("output"),
            false,
            &cancellation,
            |out| -> io::Result<()> {
                out.write_all(b"partial")?;
                cancellation.cancel("secondary");
                Err(other("invalid observation"))
            },
        )
        .unwrap_err();
        assert!(
            matches!(failure.outcome,Err(WriteIssue::Encoding(ref error)) if error.to_string()=="invalid observation")
        );
        assert!(failure.retained.is_none());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn committed_receipt_survives_cancellation_and_cleanup_can_be_retried() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("output");
        let cancellation = Cancellation::default();
        let mut owner = StagedOutput::prepare(&destination, false, &cancellation).unwrap();
        let bytes = owner
            .write(&cancellation, |out| out.write_all(b"committed"))
            .unwrap();
        let outcome = owner.publish(bytes, &cancellation);
        let directory = owner.directory.clone();
        let foreign = directory.join("foreign");
        std::fs::write(&foreign, b"leave me").unwrap();
        cancellation.cancel("during final cleanup");
        let mut failure = owner.finish(outcome).unwrap_err();
        assert_eq!(failure.outcome.as_ref().unwrap().bytes, 9);
        assert_eq!(std::fs::read(&destination).unwrap(), b"committed");
        assert!(failure.retry_cleanup().is_err());
        assert!(failure.retained.is_some());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"leave me");
        std::fs::remove_file(foreign).unwrap();
        failure.retry_cleanup().unwrap();
        assert!(failure.retained.is_none());
        assert!(!directory.exists());
        // An old cleanup receipt must not delete a new occupant of the name.
        std::fs::create_dir(&directory).unwrap();
        failure.retry_cleanup().unwrap();
        assert!(directory.exists());
    }

    #[test]
    fn substituted_staging_names_are_preserved_until_the_owner_is_restored() {
        for replace_directory in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let cancellation = Cancellation::default();
            let destination = root.path().join("output");
            let mut owner = StagedOutput::prepare(&destination, false, &cancellation).unwrap();
            let bytes = owner
                .write(&cancellation, |out| out.write_all(b"owned"))
                .unwrap();
            owner.close_file().unwrap();
            let directory = owner.directory.clone();
            let selected = if replace_directory {
                directory.clone()
            } else {
                directory.join("content")
            };
            let saved = root.path().join("saved");
            std::fs::rename(&selected, &saved).unwrap();
            if replace_directory {
                std::fs::create_dir(&selected).unwrap();
            } else {
                std::fs::write(&selected, b"foreign").unwrap();
            }
            let outcome = owner.publish(bytes, &cancellation);
            let mut failure = owner.finish(outcome).unwrap_err();
            assert!(failure.outcome.is_err());
            assert!(failure.retained.is_some());
            assert!(selected.exists());
            assert!(!destination.exists());
            if replace_directory {
                std::fs::remove_dir(&selected).unwrap();
            } else {
                assert_eq!(std::fs::read(&selected).unwrap(), b"foreign");
                std::fs::remove_file(&selected).unwrap();
            }
            std::fs::rename(saved, selected).unwrap();
            failure.retry_cleanup().unwrap();
            assert!(!directory.exists());
        }
    }
}
