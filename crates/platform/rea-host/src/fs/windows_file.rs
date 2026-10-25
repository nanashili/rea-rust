//! Read-only Windows file admission and exact-handle cleanup.
//!
//! Path admission opens the reparse point itself, so a pathname replacement
//! cannot turn a regular-file check into a different target after the check.

#[cfg(windows)]
use crate::fs::stable_file::{CloseOutcome, FileAccess, FileError, Fingerprint, IoKind, Kind};

#[cfg(windows)]
use std::{io, os::windows::ffi::OsStrExt, path::Path, ptr};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
        FILE_INFO_BY_HANDLE_CLASS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_STANDARD_INFO, FileBasicInfo, FileStandardInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx, OPEN_EXISTING, ReadFile,
    },
};

#[cfg(windows)]
#[derive(Debug)]
pub struct WindowsFiles;

#[cfg(windows)]
#[derive(Debug)]
pub struct WindowsHandle(HANDLE);

#[cfg(windows)]
// A Windows handle is an owned kernel resource. The wrapper never exposes the
// raw value across the FileAccess boundary, and each operation uses that one
// value until the wrapper is consumed by close.
unsafe impl Send for WindowsHandle {}

#[cfg(windows)]
impl FileAccess for WindowsFiles {
    type Handle = WindowsHandle;

    fn lstat(&self, path: &Path) -> Result<Fingerprint, FileError> {
        let handle = open_path(path, false)?;
        let result = fingerprint(handle.0);
        finish_temporary_handle(handle, result)
    }

    fn open_regular_candidate(&self, path: &Path) -> Result<Self::Handle, FileError> {
        open_path(path, true)
    }

    fn stat(&self, handle: &Self::Handle) -> Result<Fingerprint, FileError> {
        fingerprint(handle.0)
    }

    fn read(&self, handle: &Self::Handle, output: &mut [u8]) -> Result<usize, FileError> {
        read_handle(handle.0, output)
    }

    fn close(&self, handle: Self::Handle) -> CloseOutcome<Self::Handle> {
        let WindowsHandle(raw) = handle;
        let closed = unsafe { CloseHandle(raw) } != 0;
        if closed {
            CloseOutcome::Released
        } else {
            CloseOutcome::Retained {
                handle: WindowsHandle(raw),
                error: failure(unsafe { GetLastError() }),
            }
        }
    }
}

#[cfg(windows)]
fn open_path(path: &Path, sequential: bool) -> Result<WindowsHandle, FileError> {
    let path = wide_path(path)?;
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    if sequential {
        flags |= FILE_FLAG_SEQUENTIAL_SCAN;
    }

    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(failure(unsafe { GetLastError() }));
    }
    Ok(WindowsHandle(handle))
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Result<Vec<u16>, FileError> {
    if path.as_os_str().is_empty() {
        return Err(FileError {
            kind: IoKind::Other,
            system_code: None,
            source: io::Error::new(io::ErrorKind::InvalidInput, "empty Windows path"),
        });
    }
    Ok(path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

#[cfg(windows)]
fn finish_temporary_handle(
    handle: WindowsHandle,
    result: Result<Fingerprint, FileError>,
) -> Result<Fingerprint, FileError> {
    let WindowsHandle(raw) = handle;
    let closed = unsafe { CloseHandle(raw) } != 0;
    if !closed {
        let close_error = failure(unsafe { GetLastError() });
        return match result {
            Ok(_) => Err(close_error),
            Err(error) => Err(error),
        };
    }
    result
}

#[cfg(windows)]
fn fingerprint(handle: HANDLE) -> Result<Fingerprint, FileError> {
    let mut identity = BY_HANDLE_FILE_INFORMATION::default();
    let identity_read = unsafe { GetFileInformationByHandle(handle, &mut identity) } != 0;
    if !identity_read {
        return Err(failure(unsafe { GetLastError() }));
    }

    let standard = query_handle_info::<FILE_STANDARD_INFO>(handle, FileStandardInfo)?;
    let basic = query_handle_info::<FILE_BASIC_INFO>(handle, FileBasicInfo)?;

    let kind = if identity.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Kind::Symlink
    } else if standard.Directory {
        Kind::Other
    } else {
        Kind::Regular
    };
    let bytes = u64::try_from(standard.EndOfFile).map_err(|_| FileError {
        kind: IoKind::Other,
        system_code: None,
        source: io::Error::other("negative native file size"),
    })?;
    let file_id = (u128::from(identity.nFileIndexHigh) << 32) | u128::from(identity.nFileIndexLow);

    Ok(Fingerprint {
        kind,
        device: u64::from(identity.dwVolumeSerialNumber),
        file_id,
        bytes,
        modified_ns: i128::from(basic.LastWriteTime),
        changed_ns: i128::from(basic.ChangeTime),
    })
}

#[cfg(windows)]
fn query_handle_info<T: Copy>(
    handle: HANDLE,
    information_class: FILE_INFO_BY_HANDLE_CLASS,
) -> Result<T, FileError> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let read = unsafe {
        GetFileInformationByHandleEx(
            handle,
            information_class,
            value.as_mut_ptr().cast(),
            std::mem::size_of::<T>() as u32,
        )
    } != 0;
    if !read {
        return Err(failure(unsafe { GetLastError() }));
    }
    Ok(unsafe { value.assume_init() })
}

#[cfg(windows)]
fn read_handle(handle: HANDLE, output: &mut [u8]) -> Result<usize, FileError> {
    if output.is_empty() {
        return Ok(0);
    }
    let requested = output.len().min(u32::MAX as usize) as u32;
    let mut read = 0u32;
    let succeeded = unsafe {
        ReadFile(
            handle,
            output.as_mut_ptr().cast(),
            requested,
            &mut read,
            ptr::null_mut(),
        )
    } != 0;
    if !succeeded {
        return Err(failure(unsafe { GetLastError() }));
    }
    Ok(read as usize)
}

#[cfg(windows)]
fn failure(code: u32) -> FileError {
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_NAME,
        ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION,
    };

    let (kind, system_code) = match code {
        ERROR_FILE_NOT_FOUND => (IoKind::NotFound, Some("ERROR_FILE_NOT_FOUND")),
        ERROR_PATH_NOT_FOUND => (IoKind::NotDirectory, Some("ERROR_PATH_NOT_FOUND")),
        ERROR_FILENAME_EXCED_RANGE => (IoKind::NameTooLong, Some("ENAMETOOLONG")),
        ERROR_ACCESS_DENIED => (IoKind::AccessDenied, Some("ERROR_ACCESS_DENIED")),
        ERROR_SHARING_VIOLATION => (IoKind::AccessDenied, Some("ERROR_SHARING_VIOLATION")),
        ERROR_INVALID_NAME => (IoKind::Other, Some("ERROR_INVALID_NAME")),
        _ => (IoKind::Other, None),
    };
    FileError {
        kind,
        system_code,
        source: io::Error::from_raw_os_error(code as i32),
    }
}
