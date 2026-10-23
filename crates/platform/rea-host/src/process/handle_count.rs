//! Bounded, read-only Windows process handle-count observation.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandleCountObservation {
    Readable { count: u32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessHandleCountObserver;

impl ProcessHandleCountObserver {
    pub fn observe(&self, pid: u64) -> HandleCountObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(windows)]
fn observe_platform(pid: u64) -> HandleCountObservation {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessHandleCount, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let Ok(process_id) = u32::try_from(pid) else {
        return unavailable("process id is outside the Windows PID range");
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        return if error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND {
            HandleCountObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!(
                "OpenProcess handle-count query failed with Windows error {error}"
            ))
        };
    }

    let mut count = 0_u32;
    let count_read = unsafe { GetProcessHandleCount(handle, &mut count) } != 0;
    let query_error = (!count_read).then(|| unsafe { GetLastError() });
    let close_succeeded = unsafe { CloseHandle(handle) } != 0;
    if !close_succeeded {
        return unavailable(format!(
            "CloseHandle failed with Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    if let Some(error) = query_error {
        return unavailable(format!(
            "GetProcessHandleCount failed with Windows error {error}"
        ));
    }
    HandleCountObservation::Readable { count }
}

#[cfg(not(windows))]
fn observe_platform(_pid: u64) -> HandleCountObservation {
    unavailable("Windows process handle-count observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> HandleCountObservation {
    HandleCountObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::{HandleCountObservation, ProcessHandleCountObserver};

    #[test]
    fn observes_current_process_handle_count() {
        assert!(matches!(
            ProcessHandleCountObserver.observe(std::process::id() as u64),
            HandleCountObservation::Readable { count } if count > 0
        ));
    }

    #[test]
    fn rejects_ids_outside_the_windows_range() {
        assert!(matches!(
            ProcessHandleCountObserver.observe(u64::from(u32::MAX) + 1),
            HandleCountObservation::Unavailable { reason }
                if reason == "process id is outside the Windows PID range"
        ));
    }
}
