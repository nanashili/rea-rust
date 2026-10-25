//! Owned Windows Job Object setup for a caller-created child process.

#[cfg(windows)]
use std::cell::Cell;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT},
    System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    },
    System::SystemServices::JOB_OBJECT_MSG_JOB_MEMORY_LIMIT,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsJobLimits {
    pub memory_bytes: Option<u64>,
    pub cpu_seconds: Option<u64>,
}

impl WindowsJobLimits {
    pub fn validate(self) -> Result<(), String> {
        if self.memory_bytes == Some(0) {
            return Err("memory limit must be greater than zero".into());
        }
        if self.cpu_seconds == Some(0) {
            return Err("CPU limit must be greater than zero".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsJobLimits;

    #[test]
    fn absent_limits_are_valid() {
        assert!(
            WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn zero_limits_are_explicitly_rejected() {
        let memory = WindowsJobLimits {
            memory_bytes: Some(0),
            cpu_seconds: None,
        };
        assert_eq!(
            memory.validate().err().as_deref(),
            Some("memory limit must be greater than zero")
        );

        let cpu = WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: Some(0),
        };
        assert_eq!(
            cpu.validate().err().as_deref(),
            Some("CPU limit must be greater than zero")
        );
    }

    #[cfg(windows)]
    #[test]
    fn jobs_without_memory_limits_have_no_memory_limit_notification() {
        let job = super::OwnedWindowsJob::create(WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        })
        .expect("an unrestricted Job Object should be creatable");
        assert!(
            !job.observe_memory_limit()
                .expect("notification observation should succeed")
        );
        assert!(
            !job.observe_memory_limit()
                .expect("a second nonblocking observation should also succeed")
        );
    }

    #[cfg(windows)]
    #[test]
    fn newly_created_job_reports_no_active_processes() {
        let job = super::OwnedWindowsJob::create(WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        })
        .expect("an owned Job Object should be creatable");

        assert_eq!(
            job.active_processes()
                .expect("active process accounting should be readable"),
            0
        );
        assert!(
            !job.terminate_if_active(1)
                .expect("an empty owned family should be a termination no-op")
        );
    }
}

#[cfg(windows)]
pub struct OwnedWindowsJob {
    handle: OwnedHandle,
    completion_port: Option<OwnedHandle>,
    memory_limit_reached: Cell<bool>,
}

#[cfg(windows)]
impl OwnedWindowsJob {
    pub fn create(limits: WindowsJobLimits) -> Result<Self, String> {
        limits.validate()?;

        let raw_handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw_handle.is_null() {
            return Err("CreateJobObjectW failed".into());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw_handle) };

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        if let Some(memory) = limits.memory_bytes {
            info.JobMemoryLimit = match usize::try_from(memory) {
                Ok(value) => value,
                Err(_) => return Err("memory limit exceeds platform size".into()),
            };
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        }

        if let Some(cpu) = limits.cpu_seconds {
            let duration = i64::try_from(cpu)
                .ok()
                .and_then(|seconds| seconds.checked_mul(10_000_000))
                .ok_or("CPU limit exceeds platform size")?;
            info.BasicLimitInformation.PerJobUserTimeLimit = duration;
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        }

        let configured = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } != 0;
        if !configured {
            return Err("SetInformationJobObject failed".into());
        }

        let completion_port = if limits.memory_bytes.is_some() {
            let raw_completion_port = unsafe {
                CreateIoCompletionPort(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null_mut(),
                    handle.as_raw_handle() as usize,
                    1,
                )
            };
            if raw_completion_port.is_null() {
                return Err("CreateIoCompletionPort failed".into());
            }
            let completion_port = unsafe { OwnedHandle::from_raw_handle(raw_completion_port) };

            let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
                CompletionKey: handle.as_raw_handle(),
                CompletionPort: completion_port.as_raw_handle(),
            };
            let associated = unsafe {
                SetInformationJobObject(
                    handle.as_raw_handle(),
                    JobObjectAssociateCompletionPortInformation,
                    (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
                    std::mem::size_of_val(&association) as u32,
                )
            } != 0;
            if !associated {
                return Err("SetInformationJobObject completion port failed".into());
            }

            Some(completion_port)
        } else {
            None
        };

        Ok(Self {
            handle,
            completion_port,
            memory_limit_reached: Cell::new(false),
        })
    }

    pub fn assign(&self, process: HANDLE) -> Result<(), String> {
        if unsafe { AssignProcessToJobObject(self.handle.as_raw_handle(), process) } == 0 {
            return Err("AssignProcessToJobObject failed".into());
        }

        Ok(())
    }

    /// Create, configure, and assign a caller-created child in one ownership phase.
    pub fn create_and_assign(process: HANDLE, limits: WindowsJobLimits) -> Result<Self, String> {
        let job = Self::create(limits)?;
        job.assign(process)?;
        Ok(job)
    }

    pub(crate) fn raw_handle(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    pub fn terminate(&self, exit_code: u32) -> Result<(), String> {
        if unsafe { TerminateJobObject(self.handle.as_raw_handle(), exit_code) } == 0 {
            return Err("TerminateJobObject failed".into());
        }

        Ok(())
    }

    pub fn terminate_if_active(&self, exit_code: u32) -> Result<bool, String> {
        if self.active_processes()? == 0 {
            return Ok(false);
        }

        self.terminate(exit_code)?;
        Ok(true)
    }

    pub fn active_processes(&self) -> Result<u32, String> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let queried = unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } != 0;
        if !queried {
            return Err("QueryInformationJobObject failed".into());
        }

        Ok(info.ActiveProcesses)
    }

    pub fn peak_memory_bytes(&self) -> Result<u64, String> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let queried = unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } != 0;
        if !queried {
            return Err("QueryInformationJobObject peak memory failed".into());
        }

        Ok(info.PeakJobMemoryUsed as u64)
    }

    pub fn observe_memory_limit(&self) -> Result<bool, String> {
        let Some(completion_port) = self.completion_port.as_ref() else {
            return Ok(false);
        };

        loop {
            let mut message = 0u32;
            let mut key = 0usize;
            let mut detail: *mut OVERLAPPED = std::ptr::null_mut();
            let received = unsafe {
                GetQueuedCompletionStatus(
                    completion_port.as_raw_handle(),
                    &mut message,
                    &mut key,
                    &mut detail,
                    0,
                )
            } != 0;
            if !received {
                let error = unsafe { GetLastError() };
                if error == WAIT_TIMEOUT {
                    return Ok(self.memory_limit_reached.get());
                }
                return Err(format!(
                    "GetQueuedCompletionStatus failed with Windows error {error}"
                ));
            }
            if key == self.handle.as_raw_handle() as usize
                && message == JOB_OBJECT_MSG_JOB_MEMORY_LIMIT
            {
                self.memory_limit_reached.set(true);
            }
        }
    }
}
