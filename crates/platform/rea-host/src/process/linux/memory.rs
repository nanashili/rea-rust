//! Bounded, read-only Linux `/proc/<pid>/statm` observations.

#[cfg(target_os = "linux")]
use std::{fs, io, io::Read, path::PathBuf};

pub const MAX_PROC_STATM_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryObservation {
    Readable {
        virtual_pages: u64,
        resident_pages: u64,
        page_size_bytes: u64,
        virtual_bytes: u64,
        resident_bytes: u64,
        page_size_source: &'static str,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessMemoryObserver;

impl ProcessMemoryObserver {
    pub fn observe(&self, pid: u64) -> MemoryObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> MemoryObservation {
    let path = PathBuf::from(format!("/proc/{pid}/statm"));
    let text = match read_bounded(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return MemoryObservation::Absent {
                reason: "not-found-in-caller-pid-namespace",
            };
        }
        Err(error) => return unavailable(format!("read proc statm {path:?}: {error}")),
    };
    let mut fields = text.split_whitespace();
    let Some(virtual_pages) = fields.next().and_then(|field| field.parse().ok()) else {
        return unavailable("malformed proc statm virtual-page field");
    };
    let Some(resident_pages) = fields.next().and_then(|field| field.parse().ok()) else {
        return unavailable("malformed or short proc statm resident-page field");
    };
    let page_size_bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let Ok(page_size_bytes) = u64::try_from(page_size_bytes) else {
        return unavailable("page size could not be observed");
    };
    let (virtual_bytes, resident_bytes) =
        match convert_page_counts(virtual_pages, resident_pages, page_size_bytes) {
            Ok(bytes) => bytes,
            Err(reason) => return unavailable(reason),
        };
    MemoryObservation::Readable {
        virtual_pages,
        resident_pages,
        page_size_bytes,
        virtual_bytes,
        resident_bytes,
        page_size_source: "sysconf(_SC_PAGESIZE)",
    }
}

#[cfg(target_os = "macos")]
fn observe_platform(pid: u64) -> MemoryObservation {
    use std::mem::size_of;

    let Ok(process_id) = libc::pid_t::try_from(pid) else {
        return unavailable("process id is outside the macOS PID range");
    };

    let mut task = std::mem::MaybeUninit::<libc::proc_taskinfo>::zeroed();
    // SAFETY: PROC_PIDTASKINFO is a bounded, read-only query into an
    // initialized buffer with its exact ABI size.
    let result = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDTASKINFO,
            0,
            task.as_mut_ptr().cast(),
            size_of::<libc::proc_taskinfo>() as libc::c_int,
        )
    };
    if result <= 0 {
        return macos_process_error("proc_pidinfo task query");
    }
    if result as usize != size_of::<libc::proc_taskinfo>() {
        return unavailable(format!(
            "proc_pidinfo task query returned {result} bytes, expected {}",
            size_of::<libc::proc_taskinfo>()
        ));
    }

    // SAFETY: sysconf reads process-global page-size configuration.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let Ok(page_size_bytes) = u64::try_from(page_size) else {
        return unavailable("page size could not be observed");
    };
    if page_size_bytes == 0 {
        return unavailable("page size could not be observed");
    }

    // SAFETY: The kernel reported the complete proc_taskinfo structure.
    let task = unsafe { task.assume_init() };
    let virtual_bytes = task.pti_virtual_size;
    let resident_bytes = task.pti_resident_size;
    let Some(virtual_pages) = virtual_bytes.checked_div(page_size_bytes) else {
        return unavailable("virtual memory page conversion failed");
    };
    let Some(resident_pages) = resident_bytes.checked_div(page_size_bytes) else {
        return unavailable("resident memory page conversion failed");
    };
    MemoryObservation::Readable {
        virtual_pages,
        resident_pages,
        page_size_bytes,
        virtual_bytes,
        resident_bytes,
        page_size_source: "sysconf(_SC_PAGESIZE)",
    }
}

#[cfg(target_os = "macos")]
fn macos_process_error(operation: &str) -> MemoryObservation {
    // SAFETY: __error returns Darwin's thread-local errno slot.
    let error = unsafe { *libc::__error() };
    if error == libc::ESRCH {
        MemoryObservation::Absent {
            reason: "not-found-in-caller-process-namespace",
        }
    } else {
        unavailable(format!("{operation} failed with Darwin error {error}"))
    }
}

#[cfg(target_os = "linux")]
fn convert_page_counts(
    virtual_pages: u64,
    resident_pages: u64,
    page_size_bytes: u64,
) -> Result<(u64, u64), &'static str> {
    let virtual_bytes = virtual_pages
        .checked_mul(page_size_bytes)
        .ok_or("virtual memory byte count overflowed")?;
    let resident_bytes = resident_pages
        .checked_mul(page_size_bytes)
        .ok_or("resident memory byte count overflowed")?;
    Ok((virtual_bytes, resident_bytes))
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn observe_platform(_pid: u64) -> MemoryObservation {
    unavailable("native process memory observation is unsupported on this host")
}

#[cfg(windows)]
fn observe_platform(_pid: u64) -> MemoryObservation {
    unavailable("use the Windows process memory observer on this host")
}

fn unavailable(reason: impl Into<String>) -> MemoryObservation {
    MemoryObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &PathBuf) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_PROC_STATM_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROC_STATM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc statm exceeds observation bound",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn observes_current_process_page_counts() {
        let observation = ProcessMemoryObserver.observe(std::process::id() as u64);
        let MemoryObservation::Readable {
            virtual_pages,
            resident_pages,
            page_size_bytes,
            virtual_bytes,
            resident_bytes,
            ..
        } = observation
        else {
            panic!("current process statm should be readable");
        };
        assert!(virtual_pages >= resident_pages);
        assert!(page_size_bytes > 0);
        assert_eq!(virtual_bytes, virtual_pages * page_size_bytes);
        assert_eq!(resident_bytes, resident_pages * page_size_bytes);
    }

    #[test]
    fn rejects_short_and_overflowing_statm_fixtures() {
        assert!(parse_fixture("12").is_err());
        assert_eq!(parse_fixture("18446744073709551615 2"), Ok((u64::MAX, 2)));
        assert!(convert_page_counts(u64::MAX, 2, 4096).is_err());
        assert_eq!(parse_fixture("2 3"), Ok((2, 3)));
        assert_eq!(convert_page_counts(2, 3, 4096), Ok((8192, 12288)));
    }

    fn parse_fixture(value: &str) -> Result<(u64, u64), &'static str> {
        let mut fields = value.split_whitespace();
        let virtual_pages = fields
            .next()
            .ok_or("missing virtual pages")?
            .parse::<u64>()
            .map_err(|_| "invalid virtual pages")?;
        let resident_pages = fields
            .next()
            .ok_or("missing resident pages")?
            .parse::<u64>()
            .map_err(|_| "invalid resident pages")?;
        Ok((virtual_pages, resident_pages))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    #[test]
    fn observes_current_process_task_memory() {
        let observation = ProcessMemoryObserver.observe(std::process::id() as u64);
        let MemoryObservation::Readable {
            virtual_bytes,
            resident_bytes,
            page_size_bytes,
            virtual_pages,
            resident_pages,
            ..
        } = observation
        else {
            panic!("current process task info should be readable");
        };
        assert!(virtual_bytes >= resident_bytes);
        assert!(page_size_bytes > 0);
        assert_eq!(virtual_bytes, virtual_pages * page_size_bytes);
        assert_eq!(resident_bytes, resident_pages * page_size_bytes);
    }

    #[test]
    fn macos_resident_memory_comes_from_read_only_task_observation() {
        let observation = ProcessMemoryObserver.observe(std::process::id() as u64);
        let MemoryObservation::Readable { resident_bytes, .. } = observation else {
            panic!("current process resident memory should be readable");
        };
        assert!(resident_bytes > 0);
    }

    #[test]
    fn invalid_macos_pid_remains_unavailable_without_claiming_absence() {
        assert!(matches!(
            ProcessMemoryObserver.observe(u64::MAX),
            MemoryObservation::Unavailable { reason }
                if reason == "process id is outside the macOS PID range"
        ));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn invalid_windows_pid_remains_unavailable_without_claiming_absence() {
        assert!(matches!(
            ProcessMemoryObserver.observe(u64::MAX),
            MemoryObservation::Unavailable { reason }
                if reason == "process id is outside the Windows PID range"
        ));
    }
}
