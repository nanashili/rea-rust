//! Windows owner-only directory creation.
//!
//! Compatibility owner: the native `runtime_create` used by
//! `src/windows/WindowsPrivateRuntime.ts`, which installs a protected DACL
//! granting only the current user access when the directory is created, so
//! no inherited ACE ever applies to its contents.
//!
//! This is the only module in the crate that uses FFI.
#![allow(unsafe_code)]
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// String SID of the current process token's user.
fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no close;
    // `token` is a valid out pointer for the opened token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut length = 0u32;
        // SAFETY: a null buffer with zero length asks only for the required
        // size, written to the valid `length` out pointer.
        unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length) };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 storage keeps the TOKEN_USER header pointer-aligned.
        let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
        // SAFETY: `buffer` provides at least `length` writable, aligned bytes.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success the buffer begins with an initialized TOKEN_USER
        // whose SID points into the same live buffer.
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `user.User.Sid` is a valid SID for the buffer's lifetime and
        // `text` is a valid out pointer receiving a LocalAlloc'd string.
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `text` is a NUL-terminated UTF-16 string from the API.
        let sid = unsafe {
            let mut length = 0usize;
            while *text.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
        };
        // SAFETY: `text` was allocated by ConvertSidToStringSidW with LocalAlloc.
        unsafe { LocalFree(text.cast()) };
        Ok(sid)
    })();
    // SAFETY: `token` is the handle opened above and is closed exactly once.
    unsafe { CloseHandle(token) };
    result
}

/// Create `path` with a protected DACL granting only the current user full
/// access (inherited by every child object).
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    let sid = current_user_sid()?;
    let sddl = wide(std::ffi::OsStr::new(&format!(
        "O:{sid}D:P(A;OICI;FA;;;{sid})"
    )));
    let mut descriptor: *mut core::ffi::c_void = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `descriptor` receives a LocalAlloc'd
    // security descriptor; the size out pointer may be null.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide(path.as_os_str());
    // SAFETY: `name` is NUL-terminated and `attributes` references the live
    // descriptor for the duration of the call.
    let created = unsafe { CreateDirectoryW(name.as_ptr(), &attributes) };
    let error = (created == 0).then(io::Error::last_os_error);
    // SAFETY: the descriptor was allocated by the conversion API above.
    unsafe { LocalFree(descriptor) };
    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
