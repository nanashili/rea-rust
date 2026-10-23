//! POSIX file admission adapter. No-follow/nonblocking open closes the pathname
//! replacement window before regular-file identity is verified on the handle.
use crate::fs::stable_file::{CloseOutcome, FileAccess, FileError, Fingerprint, IoKind, Kind};
use rustix::{
    fd::{IntoRawFd, OwnedFd},
    fs::{self, FileType, Mode, OFlags, Stat},
    io::Errno,
};
use std::{io, path::Path};

#[derive(Debug)]
pub struct UnixFiles;
impl FileAccess for UnixFiles {
    type Handle = OwnedFd;
    fn lstat(&self, path: &Path) -> Result<Fingerprint, FileError> {
        fingerprint(fs::lstat(path).map_err(failure)?)
    }
    fn open_regular_candidate(&self, path: &Path) -> Result<OwnedFd, FileError> {
        fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)
    }
    fn stat(&self, handle: &OwnedFd) -> Result<Fingerprint, FileError> {
        fingerprint(fs::fstat(handle).map_err(failure)?)
    }
    fn read(&self, handle: &OwnedFd, output: &mut [u8]) -> Result<usize, FileError> {
        rustix::io::read(handle, output).map_err(failure)
    }
    fn close(&self, handle: OwnedFd) -> CloseOutcome<OwnedFd> {
        let raw = handle.into_raw_fd();
        // SAFETY: the uniquely owned descriptor is consumed here. rustix's
        // try_close contract invalidates it even on error; it is never retried
        // or reconstructed from a number that may subsequently be reused.
        match unsafe { rustix::io::try_close(raw) } {
            Ok(()) => CloseOutcome::Released,
            Err(error) => CloseOutcome::ReleasedWithError(failure(error)),
        }
    }
}

fn failure(error: Errno) -> FileError {
    let (kind, system_code) = match error {
        Errno::NOENT => (IoKind::NotFound, Some("ENOENT")),
        Errno::NOTDIR => (IoKind::NotDirectory, Some("ENOTDIR")),
        Errno::LOOP => (IoKind::SymlinkLoop, Some("ELOOP")),
        Errno::NAMETOOLONG => (IoKind::NameTooLong, Some("ENAMETOOLONG")),
        Errno::ACCESS => (IoKind::AccessDenied, Some("EACCES")),
        Errno::PERM => (IoKind::AccessDenied, Some("EPERM")),
        Errno::INTR => (IoKind::Interrupted, Some("EINTR")),
        Errno::IO => (IoKind::Other, Some("EIO")),
        _ => (IoKind::Other, None),
    };
    FileError {
        kind,
        system_code,
        source: error.into(),
    }
}

fn fingerprint(stat: Stat) -> Result<Fingerprint, FileError> {
    let kind = match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => Kind::Regular,
        FileType::Symlink => Kind::Symlink,
        _ => Kind::Other,
    };
    let bytes = u64::try_from(stat.st_size).map_err(|_| FileError {
        kind: IoKind::Other,
        system_code: None,
        source: io::Error::other("negative native file size"),
    })?;
    Ok(Fingerprint {
        kind,
        device: stat.st_dev as u64,
        file_id: stat.st_ino as u128,
        bytes,
        modified_ns: stat.st_mtime as i128 * 1_000_000_000 + stat.st_mtime_nsec as i128,
        changed_ns: stat.st_ctime as i128 * 1_000_000_000 + stat.st_ctime_nsec as i128,
    })
}
