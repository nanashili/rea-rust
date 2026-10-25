//! Windows atomic publication with explicit cleanup ownership.

use rea_core::cancellation::Cancellation;
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
};
use tempfile::Builder;
use windows_sys::Win32::Foundation::{
    CloseHandle, DELETE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_RENAME_INFO,
    FILE_RENAME_INFO_0, FILE_SHARE_READ, FILE_SHARE_WRITE, FileRenameInfo,
    GetFileInformationByHandle, OPEN_EXISTING, SetFileInformationByHandle,
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
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => output.write_str("destination already exists"),
            Self::NotFile => output.write_str("destination is not a regular file"),
            Self::Cancelled => output.write_str("publication cancelled"),
            Self::Io(error) => error.fmt(output),
            Self::Encoding(error) => error.fmt(output),
        }
    }
}

impl Error for WriteIssue {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Encoding(error) => Some(error.as_ref()),
            Self::Exists | Self::NotFile | Self::Cancelled => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Published {
    pub bytes: u64,
}

#[derive(Debug)]
pub struct WriteFailure {
    pub outcome: Result<Published, WriteIssue>,
    pub cleanup: Option<io::Error>,
    pub retained: Option<Box<StagedOutput>>,
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

    pub fn retry_cleanup(&mut self) -> io::Result<()> {
        if let Some(owner) = &mut self.retained {
            owner.cleanup()?;
        }
        self.retained = None;
        self.cleanup = None;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u32,
    index: u64,
}

fn identity(handle: HANDLE) -> Option<FileIdentity> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the caller owns or borrows this live Windows handle for the call.
    let read = unsafe { GetFileInformationByHandle(handle, &mut information) } != 0;
    if !read {
        return None;
    }
    Some(FileIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}

fn file_identity(file: &File) -> Option<FileIdentity> {
    identity(file.as_raw_handle())
}

fn directory_identity(path: &Path) -> io::Result<(OwnedHandle, FileIdentity)> {
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: the path buffer is NUL-terminated and remains live for the call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle was returned by CreateFileW and is now owned here.
    let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
    let identity = identity(owned.as_raw_handle())
        .ok_or_else(|| io::Error::other("staging directory identity unavailable"))?;
    Ok((owned, identity))
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

fn close_owned_handle(slot: &mut Option<OwnedHandle>) -> io::Result<()> {
    let Some(handle) = slot.take() else {
        return Ok(());
    };
    let raw = handle.into_raw_handle();

    // SAFETY: raw is the owned handle extracted from OwnedHandle.
    if unsafe { CloseHandle(raw) } != 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    // SAFETY: CloseHandle failed, so this process still owns the handle.
    *slot = Some(unsafe { OwnedHandle::from_raw_handle(raw) });
    Err(error)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationState {
    Staged,
    Moved,
}

/// Owns a private staging directory until publication and cleanup settle.
#[derive(Debug)]
pub struct StagedOutput {
    directory: Option<PathBuf>,
    directory_identity: Option<FileIdentity>,
    content: PathBuf,
    destination: PathBuf,
    overwrite: bool,
    file: Option<File>,
    retained_handle: Option<OwnedHandle>,
    directory_handle: Option<OwnedHandle>,
    file_identity: Option<FileIdentity>,
    publication: PublicationState,
}

impl StagedOutput {
    fn prepare(
        destination: &Path,
        overwrite: bool,
        cancellation: &Cancellation,
    ) -> Result<Self, WriteFailure> {
        active(cancellation).map_err(WriteFailure::early)?;
        let parent = destination.parent().ok_or_else(|| {
            WriteFailure::early(WriteIssue::Io(other("destination has no parent directory")))
        })?;
        let directory = Builder::new()
            .prefix(".rea-stage-")
            .tempdir_in(parent)
            .map_err(|error| WriteFailure::early(WriteIssue::Io(error)))?
            .keep();
        let content = directory.join("content");
        let directory_identity_result = directory_identity(&directory);
        let (directory_handle, directory_identity, directory_error) =
            match directory_identity_result {
                Ok((handle, identity)) => (Some(handle), Some(identity), None),
                Err(error) => (None, None, Some(error)),
            };
        let mut owner = Self {
            directory: Some(directory),
            directory_identity,
            content,
            destination: destination.to_path_buf(),
            overwrite,
            file: None,
            retained_handle: None,
            directory_handle,
            file_identity: None,
            publication: PublicationState::Staged,
        };
        if let Some(error) = directory_error {
            return match owner.finish(Err(WriteIssue::Io(error))) {
                Err(failure) => Err(failure),
                Ok(_) => unreachable!("an initialization failure cannot publish"),
            };
        }
        match OpenOptions::new()
            .access_mode(GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .write(true)
            .create_new(true)
            .open(&owner.content)
        {
            Ok(file) => {
                owner.file = Some(file);
                owner.file_identity = owner.file.as_ref().and_then(file_identity);
                if owner.file_identity.is_none() {
                    return match owner.finish(Err(WriteIssue::Io(other(
                        "staged file identity unavailable",
                    )))) {
                        Err(failure) => Err(failure),
                        Ok(_) => unreachable!("an initialization failure cannot publish"),
                    };
                }
                Ok(owner)
            }
            Err(error) => match owner.finish(Err(WriteIssue::Io(error))) {
                Err(failure) => Err(failure),
                Ok(_) => unreachable!("an initialization failure cannot publish"),
            },
        }
    }

    fn write<E: Error + Send + Sync + 'static>(
        &mut self,
        cancellation: &Cancellation,
        encode: impl FnOnce(&mut dyn Write) -> Result<(), E>,
    ) -> Result<u64, WriteIssue> {
        active(cancellation)?;
        let bytes = {
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| WriteIssue::Io(other("staged file is not open")))?;
            let mut writer = StagedWriter {
                file,
                cancellation,
                bytes: 0,
                failure: None,
            };
            let mut buffered = BufWriter::with_capacity(64 * 1024, &mut writer);
            let encoded = encode(&mut buffered);
            let flushed = if encoded.is_ok() {
                buffered.flush()
            } else {
                Ok(())
            };
            let _ = buffered.into_parts();
            if let Some(issue) = writer.failure.take() {
                return Err(issue);
            }
            encoded.map_err(|error| WriteIssue::Encoding(Box::new(error)))?;
            flushed.map_err(WriteIssue::Io)?;
            let bytes = writer.bytes;
            drop(writer);
            file.sync_all().map_err(WriteIssue::Io)?;
            bytes
        };
        active(cancellation)?;
        if self.file_identity.is_none() {
            return Err(WriteIssue::Io(other("staged file identity unavailable")));
        }
        Ok(bytes)
    }

    fn verify_directory(&mut self) -> io::Result<()> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| other("staging directory is already removed"))?;
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() {
            return Err(other("staging path is not a directory"));
        }
        let Some(expected) = self.directory_identity else {
            return Err(other("staging directory identity unavailable"));
        };
        let actual = if let Some(handle) = self.directory_handle.as_ref() {
            identity(handle.as_raw_handle())
        } else {
            let (handle, identity) = directory_identity(directory)?;
            self.directory_handle = Some(handle);
            Some(identity)
        };
        if actual != Some(expected) {
            return Err(other("staging directory identity unresolved"));
        }
        let (_, pathname_identity) = directory_identity(directory)?;
        if pathname_identity != expected {
            return Err(other("staging directory pathname changed"));
        }
        Ok(())
    }

    fn close_file(&mut self) -> io::Result<()> {
        let raw = if let Some(file) = self.file.take() {
            file.into_raw_handle()
        } else if let Some(handle) = self.retained_handle.take() {
            handle.into_raw_handle()
        } else {
            return Ok(());
        };

        // SAFETY: raw is the owned handle extracted from File or OwnedHandle.
        if unsafe { CloseHandle(raw) } != 0 {
            return Ok(());
        }

        let error = io::Error::last_os_error();
        // SAFETY: CloseHandle failed, so this process still owns the handle.
        self.retained_handle = Some(unsafe { OwnedHandle::from_raw_handle(raw) });
        Err(error)
    }

    fn reacquire_directory_handle(&mut self) -> io::Result<()> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| other("staging directory is already removed"))?;
        let (handle, identity) = directory_identity(directory)?;
        if Some(identity) != self.directory_identity {
            return Err(other("staging directory pathname changed"));
        }
        self.directory_handle = Some(handle);
        Ok(())
    }

    fn verify_content(&self) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.content)?;
        if !metadata.is_file() {
            return Err(other("staged output is not a regular file"));
        }
        let Some(expected) = self.file_identity else {
            return Err(other("staged file identity unavailable"));
        };
        let file = File::open(&self.content)?;
        if file_identity(&file) != Some(expected) {
            return Err(other("staged file identity unresolved"));
        }
        Ok(())
    }

    fn publish(
        &mut self,
        bytes: u64,
        cancellation: &Cancellation,
    ) -> Result<Published, WriteIssue> {
        active(cancellation)?;
        self.verify_directory().map_err(WriteIssue::Io)?;
        self.validate_destination()?;
        self.verify_content().map_err(WriteIssue::Io)?;
        active(cancellation)?;
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| WriteIssue::Io(other("staged file is not open")))?;
        file.sync_all().map_err(WriteIssue::Io)?;
        if self.overwrite {
            rename_handle(file, &self.destination, true).map_err(WriteIssue::Io)?;
            self.publication = PublicationState::Moved;
        } else {
            rename_handle(file, &self.destination, false).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    WriteIssue::Exists
                } else {
                    WriteIssue::Io(error)
                }
            })?;
            self.publication = PublicationState::Moved;
        }
        Ok(Published { bytes })
    }

    fn validate_destination(&self) -> Result<(), WriteIssue> {
        match fs::symlink_metadata(&self.destination) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(WriteIssue::NotFile)
            }
            Ok(_) if !self.overwrite => Err(WriteIssue::Exists),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(WriteIssue::Io(error)),
        }
    }

    pub fn cleanup(&mut self) -> io::Result<()> {
        self.close_file()?;
        let Some(directory) = self.directory.clone() else {
            return Ok(());
        };
        self.verify_directory()?;

        match self.publication {
            PublicationState::Staged => match fs::symlink_metadata(&self.content) {
                Ok(_) => {
                    self.verify_content()?;
                    fs::remove_file(&self.content)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            },
            PublicationState::Moved => match fs::symlink_metadata(&self.content) {
                Ok(_) => return Err(other("staged content reappeared after publication")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            },
        }

        self.verify_directory()?;
        close_owned_handle(&mut self.directory_handle)?;
        if let Err(error) = fs::remove_dir(&directory) {
            let reacquire = self.reacquire_directory_handle();
            if let Err(reacquire_error) = reacquire {
                return Err(io::Error::other(format!(
                    "staging cleanup failed: {error}; reacquiring directory failed: {reacquire_error}"
                )));
            }
            return Err(error);
        }
        self.directory = None;
        Ok(())
    }

    fn finish(mut self, outcome: Result<Published, WriteIssue>) -> Result<Published, WriteFailure> {
        let cleanup = self.cleanup().err();
        if cleanup.is_none() {
            return outcome.map_err(WriteFailure::early);
        }
        let staging_directory = self.directory.clone();
        let retained = Some(Box::new(self));
        Err(WriteFailure {
            outcome,
            cleanup,
            retained,
            staging_directory,
        })
    }
}

struct StagedWriter<'a> {
    file: &'a mut File,
    cancellation: &'a Cancellation,
    bytes: u64,
    failure: Option<WriteIssue>,
}

impl Write for StagedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.cancellation.reason().is_some() {
            self.failure = Some(WriteIssue::Cancelled);
            return Err(other("publication cancelled"));
        }
        let count = self.file.write(bytes)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| other("output byte count overflow"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn rename_handle(file: &File, destination: &Path, replace: bool) -> io::Result<()> {
    let destination = absolute_path(destination)?;
    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    set_rename_information(file.as_raw_handle(), &name, replace)
}

fn set_rename_information(handle: HANDLE, name: &[u16], replace: bool) -> io::Result<()> {
    let header_size = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename path is too long"))?;
    let name_length = u32::try_from(name_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "rename path is too long"))?;
    let total_size = header_size
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename path is too long"))?;
    let total_size = total_size.max(std::mem::size_of::<FILE_RENAME_INFO>());
    let mut storage = vec![0u64; total_size.div_ceil(std::mem::size_of::<u64>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: storage is aligned and large enough for the fixed header.
    unsafe {
        ptr::write(
            info,
            FILE_RENAME_INFO {
                Anonymous: FILE_RENAME_INFO_0 {
                    ReplaceIfExists: replace,
                },
                RootDirectory: std::ptr::null_mut(),
                FileNameLength: name_length,
                FileName: [0],
            },
        );
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            (storage.as_mut_ptr().cast::<u8>().add(header_size)).cast::<u16>(),
            name.len(),
        );
    }
    set_file_information(handle, FileRenameInfo, info.cast(), total_size)
}

fn set_file_information(
    handle: HANDLE,
    information_class: i32,
    information: *const std::ffi::c_void,
    size: usize,
) -> io::Result<()> {
    // SAFETY: the information buffer remains alive and immutable for the call.
    let success = unsafe {
        SetFileInformationByHandle(
            handle,
            information_class,
            information,
            u32::try_from(size)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path is too long"))?,
        )
    } != 0;
    if success {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

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

    #[test]
    fn non_overwrite_publication_removes_staged_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("output.txt");

        let published = publish(&destination, false, &Cancellation::default(), |output| {
            output.write_all(b"published")?;
            Ok::<(), io::Error>(())
        })
        .expect("publication succeeds");

        assert_eq!(published.bytes, 9);
        assert_eq!(
            fs::read(&destination).expect("published output"),
            b"published"
        );
        assert!(no_staging_directories(directory.path()));
    }

    #[test]
    fn encoding_failure_cleans_partial_staging_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("output.txt");

        let failure = publish(&destination, true, &Cancellation::default(), |output| {
            output.write_all(b"partial")?;
            Err::<(), _>(io::Error::other("encoder failed"))
        })
        .expect_err("encoding failure");

        assert!(matches!(failure.outcome, Err(WriteIssue::Encoding(_))));
        assert!(failure.cleanup.is_none());
        assert!(no_staging_directories(directory.path()));
    }

    #[test]
    fn overwrite_encoding_failure_preserves_existing_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("output.txt");
        fs::write(&destination, b"original").expect("existing output");

        let failure = publish(&destination, true, &Cancellation::default(), |output| {
            output.write_all(b"replacement")?;
            Err::<(), _>(io::Error::other("encoder failed"))
        })
        .expect_err("encoding failure");

        assert!(matches!(failure.outcome, Err(WriteIssue::Encoding(_))));
        assert_eq!(
            fs::read(&destination).expect("existing output"),
            b"original"
        );
        assert!(no_staging_directories(directory.path()));
    }

    #[test]
    fn overwrite_rejects_directory_destination_and_cleans_stage() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("output");
        fs::create_dir(&destination).expect("destination directory");

        let failure = publish(&destination, true, &Cancellation::default(), |output| {
            output.write_all(b"content")?;
            Ok::<(), io::Error>(())
        })
        .expect_err("directory destination is rejected");

        assert!(matches!(failure.outcome, Err(WriteIssue::NotFile)));
        assert!(failure.cleanup.is_none());
        assert!(destination.is_dir());
        assert!(no_staging_directories(directory.path()));
    }

    #[test]
    fn cleanup_retry_reacquires_directory_after_blocking_entry_is_removed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("output.txt");
        let mut owner = StagedOutput::prepare(&destination, false, &Cancellation::default())
            .expect("staging preparation");
        owner
            .write(&Cancellation::default(), |output| {
                output.write_all(b"content")?;
                Ok::<(), io::Error>(())
            })
            .expect("staging write");

        let blocking_entry = owner
            .directory
            .as_ref()
            .expect("staging directory")
            .join("blocking-entry");
        File::create(&blocking_entry).expect("blocking entry");

        let first_failure = owner.cleanup().expect_err("extra entry blocks cleanup");
        assert_eq!(first_failure.kind(), io::ErrorKind::DirectoryNotEmpty);
        fs::remove_file(blocking_entry).expect("remove blocking entry");
        owner.cleanup().expect("cleanup retry");
        assert!(no_staging_directories(directory.path()));
    }

    fn no_staging_directories(directory: &Path) -> bool {
        fs::read_dir(directory)
            .expect("read temporary directory")
            .map(|entry| entry.expect("read staging entry"))
            .all(|entry| {
                !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rea-stage-")
            })
    }
}
