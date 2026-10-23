//! Bounded, read-only Linux process nice-value observation.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NiceObservation {
    Readable { value: i32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessNiceObserver;
impl ProcessNiceObserver {
    pub fn observe(&self, pid: u64) -> NiceObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}
#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> NiceObservation {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return unavailable("process id is outside the Linux PID range");
    };
    unsafe {
        *libc::__errno_location() = 0;
    }
    let value = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) };
    let error = std::io::Error::last_os_error();
    if value == -1 && error.raw_os_error() == Some(libc::ESRCH) {
        return NiceObservation::Absent {
            reason: "not-found-in-caller-process-namespace",
        };
    }
    if value == -1 && error.raw_os_error().is_some_and(|code| code != 0) {
        return unavailable(format!("getpriority failed: {error}"));
    }
    NiceObservation::Readable {
        value: value as i32,
    }
}
#[cfg(not(target_os = "linux"))]
fn observe_platform(_pid: u64) -> NiceObservation {
    unavailable("Linux process nice observation is unsupported on this host")
}
fn unavailable(reason: impl Into<String>) -> NiceObservation {
    NiceObservation::Unavailable {
        reason: reason.into(),
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{NiceObservation, ProcessNiceObserver};
    #[test]
    fn observes_current_process_nice() {
        assert!(
            matches!(ProcessNiceObserver.observe(std::process::id() as u64), NiceObservation::Readable { value } if (-20..=19).contains(&value))
        );
    }
}
