//! Bounded, read-only process CPU-affinity observation.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AffinityObservation {
    Readable { cpu_count: u32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessAffinityObserver;

impl ProcessAffinityObserver {
    pub fn observe(&self, pid: u64) -> AffinityObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> AffinityObservation {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return unavailable("process id is outside the Linux PID range");
    };
    let mut mask = [0_u8; 128];
    let result = unsafe { libc::sched_getaffinity(pid, mask.len(), mask.as_mut_ptr().cast()) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            AffinityObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!("sched_getaffinity failed: {error}"))
        };
    }
    let cpu_count = mask.iter().map(|byte| byte.count_ones()).sum();
    AffinityObservation::Readable { cpu_count }
}

#[cfg(windows)]
fn observe_platform(_pid: u64) -> AffinityObservation {
    unavailable("Windows affinity observer is not wired in this slice")
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn observe_platform(_pid: u64) -> AffinityObservation {
    unavailable("process affinity observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> AffinityObservation {
    AffinityObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{AffinityObservation, ProcessAffinityObserver};
    #[test]
    fn observes_current_process_affinity() {
        assert!(
            matches!(ProcessAffinityObserver.observe(std::process::id() as u64), AffinityObservation::Readable { cpu_count } if cpu_count > 0)
        );
    }
}
