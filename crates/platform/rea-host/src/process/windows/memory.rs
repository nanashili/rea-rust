//! Bounded, read-only Windows process memory observations.
//!
//! The observer obtains one query handle and validates the process identity on
//! that handle before reading memory counters. A PID by itself is never used
//! as proof that the observed process is still the selected process.

pub use crate::process::linux::memory::MemoryObservation;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessMemoryObserver;

impl ProcessMemoryObserver {
    pub fn observe(&self, pid: u64) -> MemoryObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }

        let Ok(process_id) = u32::try_from(pid) else {
            return unavailable("process id is outside the Windows PID range");
        };

        observe_windows_process(process_id)
    }
}

#[cfg(windows)]
fn observe_windows_process(pid: u32) -> MemoryObservation {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return classify_open_error(unsafe { GetLastError() });
    }

    let identity_read = read_creation_time(handle);
    let identity_error = (!identity_read).then(|| unsafe { GetLastError() });

    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
    counters.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let counters_read = unsafe {
        GetProcessMemoryInfo(
            handle,
            &mut counters,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    } != 0;
    let counters_error = (!counters_read).then(|| unsafe { GetLastError() });

    let mut system_info: SYSTEM_INFO = unsafe { zeroed() };
    unsafe { GetSystemInfo(&mut system_info) };
    let page_size_bytes = u64::from(system_info.dwPageSize);

    let close_succeeded = unsafe { CloseHandle(handle) } != 0;
    if !close_succeeded {
        return unavailable(format!(
            "CloseHandle failed with Windows error {}",
            unsafe { GetLastError() }
        ));
    }

    if let Some(error) = identity_error {
        return classify_query_error("GetProcessTimes", error);
    }
    if let Some(error) = counters_error {
        return classify_query_error("GetProcessMemoryInfo", error);
    }

    project_counters(
        counters.PagefileUsage as u64,
        counters.WorkingSetSize as u64,
        page_size_bytes,
    )
}

#[cfg(windows)]
fn read_creation_time(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut creation = std::mem::MaybeUninit::<FILETIME>::zeroed();
    let mut exit = std::mem::MaybeUninit::<FILETIME>::zeroed();
    let mut kernel = std::mem::MaybeUninit::<FILETIME>::zeroed();
    let mut user = std::mem::MaybeUninit::<FILETIME>::zeroed();
    let read = unsafe {
        GetProcessTimes(
            handle,
            creation.as_mut_ptr(),
            exit.as_mut_ptr(),
            kernel.as_mut_ptr(),
            user.as_mut_ptr(),
        )
    } != 0;
    if !read {
        return false;
    }

    let creation = unsafe { creation.assume_init() };
    creation.dwHighDateTime != 0 || creation.dwLowDateTime != 0
}

#[cfg(windows)]
fn classify_open_error(error: u32) -> MemoryObservation {
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND};

    match error {
        ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => MemoryObservation::Absent {
            reason: "not-found-in-caller-process-namespace",
        },
        _ => classify_query_error("OpenProcess", error),
    }
}

#[cfg(windows)]
fn classify_query_error(operation: &str, error: u32) -> MemoryObservation {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    if error == ERROR_ACCESS_DENIED {
        unavailable(format!(
            "access denied while reading process memory ({operation})"
        ))
    } else {
        unavailable(format!("{operation} failed with Windows error {error}"))
    }
}

#[cfg(any(windows, test))]
fn project_counters(
    virtual_bytes: u64,
    resident_bytes: u64,
    page_size_bytes: u64,
) -> MemoryObservation {
    if page_size_bytes == 0 {
        return unavailable("Windows page size could not be observed");
    }

    MemoryObservation::Readable {
        virtual_pages: virtual_bytes / page_size_bytes,
        resident_pages: resident_bytes / page_size_bytes,
        page_size_bytes,
        virtual_bytes,
        resident_bytes,
        page_size_source: "GetSystemInfo.dwPageSize",
    }
}

#[cfg(not(windows))]
fn observe_windows_process(_pid: u32) -> MemoryObservation {
    unavailable("Windows process memory observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> MemoryObservation {
    MemoryObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_windows_counters_without_changing_byte_values() {
        let observation = project_counters(4097, 2049, 4096);

        assert_eq!(
            observation,
            MemoryObservation::Readable {
                virtual_pages: 1,
                resident_pages: 0,
                page_size_bytes: 4096,
                virtual_bytes: 4097,
                resident_bytes: 2049,
                page_size_source: "GetSystemInfo.dwPageSize",
            }
        );
    }

    #[test]
    fn zero_page_size_remains_unavailable() {
        assert!(matches!(
            project_counters(1, 1, 0),
            MemoryObservation::Unavailable { .. }
        ));
    }
}
