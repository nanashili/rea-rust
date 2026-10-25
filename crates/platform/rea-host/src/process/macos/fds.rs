//! Bounded, read-only process file-descriptor metadata.

pub const MAX_PROCESS_DESCRIPTORS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessDescriptor {
    pub fd: i32,
    pub kind: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DescriptorObservation {
    Readable {
        descriptors: Vec<ProcessDescriptor>,
        complete: bool,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessDescriptorObserver;

impl ProcessDescriptorObserver {
    pub fn observe(&self, pid: u64) -> DescriptorObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(target_os = "macos")]
fn observe_platform(pid: u64) -> DescriptorObservation {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return unavailable("process id is outside the macOS PID range");
    };
    let entry_size = std::mem::size_of::<libc::proc_fdinfo>();
    let mut storage = vec![0_u8; entry_size * MAX_PROCESS_DESCRIPTORS];
    // SAFETY: `storage` owns writable capacity for the bounded byte count and
    // all scalar arguments remain valid for the duration of proc_pidinfo.
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            storage.as_mut_ptr().cast(),
            storage.len() as libc::c_int,
        )
    };
    if result <= 0 {
        // SAFETY: libc::__error returns the calling thread's valid errno slot.
        let error = unsafe { *libc::__error() };
        return if error == libc::ESRCH {
            DescriptorObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!(
                "proc_pidinfo descriptor query failed with Darwin error {error}"
            ))
        };
    }
    let bytes = result as usize;
    if bytes > storage.len() || bytes % entry_size != 0 {
        return unavailable("proc_pidinfo returned a malformed descriptor list");
    }
    let descriptors = storage[..bytes]
        .chunks_exact(entry_size)
        .map(|entry| {
            // SAFETY: chunks_exact uses the exact ABI size of proc_fdinfo and
            // the kernel filled the complete returned byte range.
            let info = unsafe { entry.as_ptr().cast::<libc::proc_fdinfo>().read_unaligned() };
            ProcessDescriptor {
                fd: info.proc_fd,
                kind: info.proc_fdtype,
            }
        })
        .collect();
    DescriptorObservation::Readable {
        descriptors,
        complete: bytes < storage.len(),
    }
}

#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> DescriptorObservation {
    let path = format!("/proc/{pid}/fd");
    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DescriptorObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            };
        }
        Err(error) => {
            return unavailable(format!(
                "/proc descriptor directory could not be read: {error}"
            ));
        }
    };

    let mut descriptors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return unavailable(format!("/proc descriptor entry could not be read: {error}"));
            }
        };
        if descriptors.len() == MAX_PROCESS_DESCRIPTORS {
            return DescriptorObservation::Readable {
                descriptors,
                complete: false,
            };
        }

        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let target = match std::fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return DescriptorObservation::Unavailable {
                    reason: "descriptor disappeared during observation".into(),
                };
            }
            Err(error) => {
                return unavailable(format!("descriptor metadata could not be read: {error}"));
            }
        };
        descriptors.push(ProcessDescriptor {
            fd,
            kind: linux_descriptor_kind(target.to_string_lossy().as_ref()),
        });
    }

    DescriptorObservation::Readable {
        descriptors,
        complete: true,
    }
}

#[cfg(target_os = "linux")]
fn linux_descriptor_kind(target: &str) -> u32 {
    if target.starts_with("socket:") {
        1
    } else if target.starts_with("pipe:") {
        2
    } else if target.starts_with("anon_inode:") {
        3
    } else {
        0
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
fn observe_platform(_pid: u64) -> DescriptorObservation {
    unavailable("process descriptor observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> DescriptorObservation {
    DescriptorObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{DescriptorObservation, MAX_PROCESS_DESCRIPTORS, ProcessDescriptorObserver};

    #[test]
    fn observes_current_process_descriptors_with_a_bound() {
        let observation = ProcessDescriptorObserver.observe(std::process::id() as u64);
        let DescriptorObservation::Readable {
            descriptors,
            complete,
        } = observation
        else {
            panic!("current process descriptors should be readable");
        };
        assert!(complete);
        assert!(descriptors.len() <= MAX_PROCESS_DESCRIPTORS);
        assert!(descriptors.iter().all(|descriptor| descriptor.fd >= 0));
    }

    #[test]
    fn rejects_pid_values_outside_the_macos_range() {
        assert!(matches!(
            ProcessDescriptorObserver.observe(u64::MAX),
            DescriptorObservation::Unavailable { reason }
                if reason == "process id is outside the macOS PID range"
        ));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::{DescriptorObservation, MAX_PROCESS_DESCRIPTORS, ProcessDescriptorObserver};

    #[test]
    fn observes_current_process_descriptors_with_a_bound() {
        let observation = ProcessDescriptorObserver.observe(std::process::id() as u64);
        let DescriptorObservation::Readable {
            descriptors,
            complete,
        } = observation
        else {
            panic!("current process descriptors should be readable");
        };
        assert!(complete);
        assert!(descriptors.len() <= MAX_PROCESS_DESCRIPTORS);
        assert!(descriptors.iter().all(|descriptor| descriptor.fd >= 0));
    }

    #[test]
    fn reports_absent_processes_without_exposing_fd_targets() {
        assert!(matches!(
            ProcessDescriptorObserver.observe(u64::MAX),
            DescriptorObservation::Absent { reason }
                if reason == "not-found-in-caller-process-namespace"
        ));
    }
}
