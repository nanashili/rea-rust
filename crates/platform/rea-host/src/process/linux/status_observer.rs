//! Bounded, structured Linux `/proc/<pid>/status` observations.

#[cfg(target_os = "linux")]
use std::{fs, io, io::Read, path::PathBuf};

pub const MAX_PROC_STATUS_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusObservation {
    Readable {
        name: Option<String>,
        uid: Option<u64>,
        gid: Option<u64>,
        parent_pid: Option<u64>,
        threads: Option<u64>,
        state: Option<String>,
        unknown_fields: Vec<&'static str>,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessStatusObserver;

impl ProcessStatusObserver {
    pub fn observe(&self, pid: u64) -> StatusObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> StatusObservation {
    let path = PathBuf::from(format!("/proc/{pid}/status"));
    let text = match read_bounded(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return StatusObservation::Absent {
                reason: "not-found-in-caller-pid-namespace",
            };
        }
        Err(error) => return unavailable(format!("read proc status {path:?}: {error}")),
    };
    parse_status(&text)
}

#[cfg(target_os = "macos")]
fn observe_platform(pid: u64) -> StatusObservation {
    use std::mem::size_of;

    let Ok(process_id) = libc::pid_t::try_from(pid) else {
        return unavailable("process id is outside the macOS PID range");
    };

    let mut bsd = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: PROC_PIDTBSDINFO is a bounded, read-only query into an
    // initialized buffer with its exact ABI size.
    let bsd_size = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDTBSDINFO,
            0,
            bsd.as_mut_ptr().cast(),
            size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if bsd_size == 0 {
        // SAFETY: __error returns Darwin's thread-local errno slot.
        let error = unsafe { *libc::__error() };
        return if error == libc::ESRCH {
            StatusObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!(
                "proc_pidinfo BSD query failed with Darwin error {error}"
            ))
        };
    }
    if bsd_size as usize != size_of::<libc::proc_bsdinfo>() {
        return unavailable(format!(
            "proc_pidinfo BSD query returned {bsd_size} bytes, expected {}",
            size_of::<libc::proc_bsdinfo>()
        ));
    }

    // SAFETY: The kernel reported the complete proc_bsdinfo structure.
    let bsd = unsafe { bsd.assume_init() };
    let mut unknown_fields = Vec::new();
    let name = macos_process_name(&bsd.pbi_comm);
    if name.is_none() {
        unknown_fields.push("name");
    }

    let mut task = std::mem::MaybeUninit::<libc::proc_taskinfo>::zeroed();
    // SAFETY: PROC_PIDTASKINFO is a bounded, read-only query into an
    // initialized buffer with its exact ABI size.
    let task_size = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDTASKINFO,
            0,
            task.as_mut_ptr().cast(),
            size_of::<libc::proc_taskinfo>() as libc::c_int,
        )
    };
    let threads = if task_size as usize == size_of::<libc::proc_taskinfo>() {
        // SAFETY: The kernel reported the complete proc_taskinfo structure.
        Some(unsafe { task.assume_init().pti_threadnum as u64 })
    } else {
        unknown_fields.push("threads");
        None
    };

    StatusObservation::Readable {
        name,
        uid: Some(u64::from(bsd.pbi_uid)),
        gid: Some(u64::from(bsd.pbi_gid)),
        parent_pid: Some(u64::from(bsd.pbi_ppid)),
        threads,
        state: Some(macos_process_state(bsd.pbi_status)),
        unknown_fields,
    }
}

#[cfg(target_os = "macos")]
fn macos_process_name(bytes: &[libc::c_char]) -> Option<String> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let bytes = bytes[..end]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(target_os = "macos")]
fn macos_process_state(status: u32) -> String {
    let state = match status {
        1 => "idle",
        2 => "running",
        3 => "sleeping",
        4 => "stopped",
        5 => "zombie",
        6 => "waiting",
        _ => "unknown",
    };
    if state == "unknown" {
        format!("unknown({status})")
    } else {
        state.to_owned()
    }
}

#[cfg(windows)]
fn observe_platform(pid: u64) -> StatusObservation {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // Windows reports this sentinel when a process has not exited yet.  The
    // windows-sys bindings do not expose it on every supported SDK version.
    const STILL_ACTIVE: u32 = 259;

    let Ok(process_id) = u32::try_from(pid) else {
        return unavailable("process id is outside the Windows PID range");
    };
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        return if error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND {
            StatusObservation::Absent {
                reason: "not-found-in-caller-process-namespace",
            }
        } else {
            unavailable(format!(
                "OpenProcess status query failed with Windows error {error}"
            ))
        };
    }

    let mut exit_code = 0_u32;
    let exit_code_read = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
    let exit_error = (!exit_code_read).then(|| unsafe { GetLastError() });
    let close_succeeded = unsafe { CloseHandle(handle) } != 0;
    if !close_succeeded {
        return unavailable(format!(
            "CloseHandle failed with Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    if let Some(error) = exit_error {
        return unavailable(format!(
            "GetExitCodeProcess failed with Windows error {error}"
        ));
    }

    let state = if exit_code == STILL_ACTIVE {
        "running".to_owned()
    } else {
        format!("exited({exit_code})")
    };
    StatusObservation::Readable {
        name: None,
        uid: None,
        gid: None,
        parent_pid: None,
        threads: None,
        state: Some(state),
        unknown_fields: vec!["name", "uid", "gid", "ppid", "threads"],
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn observe_platform(_pid: u64) -> StatusObservation {
    unavailable("native process status observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> StatusObservation {
    StatusObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &PathBuf) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_PROC_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROC_STATUS_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc status exceeds observation bound",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(target_os = "linux")]
fn parse_status(text: &str) -> StatusObservation {
    let mut name = None;
    let mut uid = None;
    let mut gid = None;
    let mut parent_pid = None;
    let mut threads = None;
    let mut state = None;
    let mut unknown_fields = Vec::new();

    for line in text.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field {
            "Name" => assign_text(&mut name, value, "name", &mut unknown_fields),
            "Uid" => assign_effective_id(&mut uid, value, "uid", &mut unknown_fields),
            "Gid" => assign_effective_id(&mut gid, value, "gid", &mut unknown_fields),
            "PPid" => assign_number(&mut parent_pid, value, "ppid", &mut unknown_fields),
            "Threads" => assign_number(&mut threads, value, "threads", &mut unknown_fields),
            "State" => assign_state(&mut state, value, &mut unknown_fields),
            _ => {}
        }
    }

    add_missing(&mut unknown_fields, name.is_none(), "name");
    add_missing(&mut unknown_fields, uid.is_none(), "uid");
    add_missing(&mut unknown_fields, gid.is_none(), "gid");
    add_missing(&mut unknown_fields, parent_pid.is_none(), "ppid");
    add_missing(&mut unknown_fields, threads.is_none(), "threads");
    add_missing(&mut unknown_fields, state.is_none(), "state");

    StatusObservation::Readable {
        name,
        uid,
        gid,
        parent_pid,
        threads,
        state,
        unknown_fields,
    }
}

#[cfg(target_os = "linux")]
fn add_missing(unknown: &mut Vec<&'static str>, missing: bool, label: &'static str) {
    if missing && !unknown.contains(&label) {
        unknown.push(label);
    }
}

#[cfg(target_os = "linux")]
fn assign_text(
    slot: &mut Option<String>,
    value: &str,
    label: &'static str,
    unknown: &mut Vec<&'static str>,
) {
    if slot.is_some() || value.is_empty() {
        unknown.push(label);
    } else {
        *slot = Some(value.to_owned());
    }
}

#[cfg(target_os = "linux")]
fn assign_effective_id(
    slot: &mut Option<u64>,
    value: &str,
    label: &'static str,
    unknown: &mut Vec<&'static str>,
) {
    let fields: Vec<_> = value.split_whitespace().collect();
    let parsed = fields.get(1).and_then(|field| field.parse().ok());
    if slot.is_some() || fields.len() != 4 || parsed.is_none() {
        unknown.push(label);
    } else {
        *slot = parsed;
    }
}

#[cfg(target_os = "linux")]
fn assign_number(
    slot: &mut Option<u64>,
    value: &str,
    label: &'static str,
    unknown: &mut Vec<&'static str>,
) {
    match (slot.is_none(), value.parse().ok()) {
        (true, Some(value)) => *slot = Some(value),
        _ => unknown.push(label),
    }
}

#[cfg(target_os = "linux")]
fn assign_state(slot: &mut Option<String>, value: &str, unknown: &mut Vec<&'static str>) {
    let state = value
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 1);
    if slot.is_some() || state.is_none() {
        unknown.push("state");
    } else {
        *slot = state.map(str::to_owned);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_only_structured_status_fields() {
        let StatusObservation::Readable {
            name,
            uid,
            gid,
            parent_pid,
            threads,
            state,
            unknown_fields,
        } = parse_status(
            "Name:\tworker\nUid:\t1000\t1001\t1002\t1003\nGid:\t20\t21\t22\t23\nPPid:\t7\nThreads:\t3\nState:\tR (running)\nVmRSS: ignored\n",
        )
        else {
            panic!("fixture should be readable");
        };
        assert_eq!(name.as_deref(), Some("worker"));
        assert_eq!(uid, Some(1001));
        assert_eq!(gid, Some(21));
        assert_eq!(parent_pid, Some(7));
        assert_eq!(threads, Some(3));
        assert_eq!(state.as_deref(), Some("R"));
        assert!(unknown_fields.is_empty());
    }

    #[test]
    fn retains_unknown_fields_for_missing_or_malformed_values() {
        let StatusObservation::Readable {
            uid,
            parent_pid,
            unknown_fields,
            ..
        } = parse_status("Name:\nUid:\t1\tbad\t3\t4\nPPid:\tbad\nThreads:\t2\nState:\tbroken\n")
        else {
            panic!("fixture should be readable");
        };
        assert!(uid.is_none());
        assert!(parent_pid.is_none());
        assert!(unknown_fields.contains(&"name"));
        assert!(unknown_fields.contains(&"uid"));
        assert!(unknown_fields.contains(&"ppid"));
        assert!(unknown_fields.contains(&"state"));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    #[test]
    fn observes_current_macos_process_with_bsd_and_task_facts() {
        let observation = ProcessStatusObserver.observe(std::process::id() as u64);

        match observation {
            StatusObservation::Readable {
                name,
                uid,
                gid,
                parent_pid,
                threads,
                state,
                ..
            } => {
                assert!(name.is_some());
                assert!(uid.is_some());
                assert!(gid.is_some());
                assert!(parent_pid.is_some());
                assert!(threads.is_some());
                assert!(state.is_some());
            }
            other => panic!("expected readable macOS status, got {other:?}"),
        }
    }

    #[test]
    fn invalid_macos_pid_remains_unavailable_without_claiming_absence() {
        assert!(matches!(
            ProcessStatusObserver.observe(u64::MAX),
            StatusObservation::Unavailable { reason }
                if reason == "process id is outside the macOS PID range"
        ));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{ProcessStatusObserver, StatusObservation};

    #[test]
    fn observes_current_process_exit_state() {
        let observation = ProcessStatusObserver.observe(std::process::id() as u64);
        assert!(matches!(
            observation,
            StatusObservation::Readable {
                state: Some(state),
                ..
            } if state == "running"
        ));
    }

    #[test]
    fn rejects_process_ids_outside_the_windows_range() {
        assert!(matches!(
            ProcessStatusObserver.observe(u64::from(u32::MAX) + 1),
            StatusObservation::Unavailable { reason }
                if reason == "process id is outside the Windows PID range"
        ));
    }
}
