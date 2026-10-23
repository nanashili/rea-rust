//! Bounded, read-only Windows process priority observation.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PriorityObservation {
    Readable { class: u32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessPriorityObserver;

impl ProcessPriorityObserver {
    pub fn observe(&self, pid: u64) -> PriorityObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(windows)]
fn observe_platform(pid: u64) -> PriorityObservation {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::System::Threading::{
        GetPriorityClass, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let Ok(process_id) = u32::try_from(pid) else {
        return unavailable("process id is outside the Windows PID range");
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        return if error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND {
            PriorityObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!(
                "OpenProcess priority query failed with Windows error {error}"
            ))
        };
    }
    let class = unsafe { GetPriorityClass(handle) };
    let query_error = (class == 0).then(|| unsafe { GetLastError() });
    let closed = unsafe { CloseHandle(handle) } != 0;
    if !closed {
        return unavailable(format!(
            "CloseHandle failed with Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    if let Some(error) = query_error {
        return unavailable(format!(
            "GetPriorityClass failed with Windows error {error}"
        ));
    }
    PriorityObservation::Readable { class }
}

#[cfg(not(windows))]
fn observe_platform(_pid: u64) -> PriorityObservation {
    unavailable("Windows process priority observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> PriorityObservation {
    PriorityObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::{PriorityObservation, ProcessPriorityObserver};
    #[test]
    fn observes_current_process_priority() {
        assert!(matches!(
            ProcessPriorityObserver.observe(std::process::id() as u64),
            PriorityObservation::Readable { class } if class != 0
        ));
    }
}
