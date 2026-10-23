//! Bounded, read-only Windows process I/O accounting.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIoCounters {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_operations: u64,
    pub write_operations: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoCountersObservation {
    Readable(ProcessIoCounters),
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessIoCountersObserver;

impl ProcessIoCountersObserver {
    pub fn observe(&self, pid: u64) -> IoCountersObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(windows)]
fn observe_platform(pid: u64) -> IoCountersObservation {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessIoCounters, IO_COUNTERS, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let Ok(process_id) = u32::try_from(pid) else {
        return unavailable("process id is outside the Windows PID range");
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        return if error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND {
            IoCountersObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!(
                "OpenProcess I/O query failed with Windows error {error}"
            ))
        };
    }

    let mut counters: IO_COUNTERS = unsafe { std::mem::zeroed() };
    let counters_read = unsafe { GetProcessIoCounters(handle, &mut counters) } != 0;
    let query_error = (!counters_read).then(|| unsafe { GetLastError() });
    let close_succeeded = unsafe { CloseHandle(handle) } != 0;
    if !close_succeeded {
        return unavailable(format!(
            "CloseHandle failed with Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    if let Some(error) = query_error {
        return unavailable(format!(
            "GetProcessIoCounters failed with Windows error {error}"
        ));
    }
    IoCountersObservation::Readable(ProcessIoCounters {
        read_bytes: counters.ReadTransferCount,
        write_bytes: counters.WriteTransferCount,
        read_operations: counters.ReadOperationCount,
        write_operations: counters.WriteOperationCount,
    })
}

#[cfg(not(windows))]
fn observe_platform(_pid: u64) -> IoCountersObservation {
    unavailable("Windows process I/O observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> IoCountersObservation {
    IoCountersObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::{IoCountersObservation, ProcessIoCountersObserver};

    #[test]
    fn observes_current_process_io_counters() {
        assert!(matches!(
            ProcessIoCountersObserver.observe(std::process::id() as u64),
            IoCountersObservation::Readable(_)
        ));
    }

    #[test]
    fn rejects_ids_outside_the_windows_range() {
        assert!(matches!(
            ProcessIoCountersObserver.observe(u64::from(u32::MAX) + 1),
            IoCountersObservation::Unavailable { reason }
                if reason == "process id is outside the Windows PID range"
        ));
    }
}
