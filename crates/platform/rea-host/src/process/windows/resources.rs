//! Owned Windows process resource limits.
//!
//! A resource owner is created before a child is admitted to the launcher. On
//! Windows the owner is a Job Object, which applies limits to the child and
//! any descendants. Other hosts report the unsupported boundary explicitly.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsResourceLimits {
    pub working_set_bytes: u64,
    pub cpu_seconds: u64,
}

impl WindowsResourceLimits {
    fn validate(self) -> Result<(), &'static str> {
        if self.working_set_bytes == 0 {
            return Err("working-set limit must be greater than zero");
        }
        if self.cpu_seconds == 0 {
            return Err("CPU limit must be greater than zero");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum WindowsResourceSetup {
    Unsupported {
        reason: &'static str,
    },
    Failed {
        operation: &'static str,
        reason: String,
    },
    #[cfg(windows)]
    Owned(WindowsOwnedResources),
}

impl PartialEq for WindowsResourceSetup {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unsupported { reason: left }, Self::Unsupported { reason: right }) => {
                left == right
            }
            (
                Self::Failed {
                    operation: left_operation,
                    reason: left_reason,
                },
                Self::Failed {
                    operation: right_operation,
                    reason: right_reason,
                },
            ) => left_operation == right_operation && left_reason == right_reason,
            #[cfg(windows)]
            (Self::Owned(_), Self::Owned(_)) => false,
            _ => false,
        }
    }
}

impl Eq for WindowsResourceSetup {}

/// Prepare a resource owner without taking ownership of any process.
pub fn prepare_owned_resource_limits(limits: WindowsResourceLimits) -> WindowsResourceSetup {
    if let Err(reason) = limits.validate() {
        return WindowsResourceSetup::Failed {
            operation: "validate_limits",
            reason: reason.to_owned(),
        };
    }

    #[cfg(windows)]
    {
        return match WindowsOwnedResources::create(limits) {
            Ok(resources) => WindowsResourceSetup::Owned(resources),
            Err(failure) => WindowsResourceSetup::Failed {
                operation: failure.operation,
                reason: failure.reason,
            },
        };
    }

    #[cfg(not(windows))]
    {
        let _ = limits;
        WindowsResourceSetup::Unsupported {
            reason: "Windows Job Object resource enforcement is not available in this host boundary",
        }
    }
}

#[cfg(windows)]
pub struct WindowsOwnedResources {
    job: crate::process::windows::job::OwnedWindowsJob,
}

#[cfg(windows)]
impl std::fmt::Debug for WindowsOwnedResources {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsOwnedResources")
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsResourceFailure {
    operation: &'static str,
    reason: String,
}

#[cfg(windows)]
impl WindowsOwnedResources {
    fn create(limits: WindowsResourceLimits) -> Result<Self, WindowsResourceFailure> {
        let job_limits = crate::process::windows::job::WindowsJobLimits {
            memory_bytes: Some(limits.working_set_bytes),
            cpu_seconds: Some(limits.cpu_seconds),
        };

        Self::create_job(job_limits)
    }

    pub(crate) fn create_from_job_limits(
        limits: crate::process::windows::job::WindowsJobLimits,
    ) -> Result<Self, String> {
        Self::create_job(limits).map_err(|failure| failure.reason)
    }

    fn create_job(
        limits: crate::process::windows::job::WindowsJobLimits,
    ) -> Result<Self, WindowsResourceFailure> {
        crate::process::windows::job::OwnedWindowsJob::create(limits)
            .map(|job| Self { job })
            .map_err(|reason| WindowsResourceFailure {
                operation: "create_job",
                reason,
            })
    }

    /// Assign only a caller-created child to this owner.
    pub(crate) fn assign_child(
        &self,
        process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        self.job.assign(process)
    }

    pub(crate) fn raw_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.job.raw_handle()
    }

    pub(crate) fn terminate(&self, exit_code: u32) -> Result<(), String> {
        self.job.terminate(exit_code)
    }

    pub(crate) fn terminate_if_active(&self, exit_code: u32) -> Result<bool, String> {
        self.job.terminate_if_active(exit_code)
    }

    pub(crate) fn active_processes(&self) -> Result<u32, String> {
        self.job.active_processes()
    }

    pub(crate) fn peak_memory_bytes(&self) -> Result<u64, String> {
        self.job.peak_memory_bytes()
    }

    pub(crate) fn observe_memory_limit(&self) -> Result<bool, String> {
        self.job.observe_memory_limit()
    }
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_an_owned_job_without_a_process_target() {
        let setup = prepare_owned_resource_limits(WindowsResourceLimits {
            working_set_bytes: 16 * 1024 * 1024,
            cpu_seconds: 30,
        });

        assert!(matches!(setup, WindowsResourceSetup::Owned(_)));
    }

    #[test]
    fn rejects_partial_limits_before_creating_an_owner() {
        let setup = prepare_owned_resource_limits(WindowsResourceLimits {
            working_set_bytes: 0,
            cpu_seconds: 30,
        });

        assert_eq!(
            setup,
            WindowsResourceSetup::Failed {
                operation: "validate_limits",
                reason: "working-set limit must be greater than zero".into(),
            }
        );
    }
}

#[cfg(not(windows))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_setup_does_not_claim_job_ownership() {
        assert_eq!(
            prepare_owned_resource_limits(WindowsResourceLimits {
                working_set_bytes: 1,
                cpu_seconds: 1,
            }),
            WindowsResourceSetup::Unsupported {
                reason: "Windows Job Object resource enforcement is not available in this host boundary",
            }
        );
    }

    #[test]
    fn invalid_limits_are_reported_before_unsupported_host_state() {
        assert!(matches!(
            prepare_owned_resource_limits(WindowsResourceLimits {
                working_set_bytes: 0,
                cpu_seconds: 1,
            }),
            WindowsResourceSetup::Failed {
                operation: "validate_limits",
                ..
            }
        ));
    }
}
