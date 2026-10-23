//! Bounded, read-only Linux scheduler-policy observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerObservation {
    Readable { policy: i32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessSchedulerObserver;
impl ProcessSchedulerObserver {
    pub fn observe(&self, pid: u64) -> SchedulerObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}
#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> SchedulerObservation {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return unavailable("process id is outside the Linux PID range");
    };
    unsafe {
        *libc::__errno_location() = 0;
    }
    let policy = unsafe { libc::sched_getscheduler(pid) };
    if policy == -1 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            SchedulerObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!("sched_getscheduler failed: {error}"))
        };
    }
    SchedulerObservation::Readable { policy }
}
#[cfg(not(target_os = "linux"))]
fn observe_platform(_pid: u64) -> SchedulerObservation {
    unavailable("Linux scheduler observation is unsupported on this host")
}
fn unavailable(reason: impl Into<String>) -> SchedulerObservation {
    SchedulerObservation::Unavailable {
        reason: reason.into(),
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{ProcessSchedulerObserver, SchedulerObservation};
    #[test]
    fn observes_current_process_policy() {
        assert!(
            matches!(ProcessSchedulerObserver.observe(std::process::id() as u64), SchedulerObservation::Readable { policy } if policy >= 0)
        );
    }
}
