//! Read-only Windows process identity observations.
//!
//! This boundary opens only query handles.  It never returns a process
//! control handle and never treats an unreadable generation as absent.

pub use crate::process::linux::identity::{Generation, Observation, Relation};

/// Read-only observer for caller-selected Windows process IDs.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsProcessIdentityObserver;

impl WindowsProcessIdentityObserver {
    /// Observe one process generation without enumerating or controlling it.
    pub fn observe(&self, pid: u64) -> Observation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }

        let Ok(pid) = u32::try_from(pid) else {
            return unavailable("process id is outside the Windows PID range");
        };

        observe_windows_process(pid)
    }

    /// Compare two reads of one PID while retaining unknown and replacement
    /// outcomes for callers that need to bind a later fact to a generation.
    pub fn generation(&self, before: &Observation, after: &Observation) -> Generation {
        crate::process::linux::identity::generation(before, after)
    }
}

#[cfg(windows)]
fn observe_windows_process(pid: u32) -> Observation {
    let identity = match process_creation_identity(pid) {
        Ok(identity) => identity,
        Err(ProcessError::Absent { reason }) => return Observation::Absent { reason },
        Err(ProcessError::Unavailable(reason)) => return unavailable(reason),
    };

    let lifecycle = process_lifecycle(pid);
    let relation = stable_parent_relation(pid);

    Observation::Readable {
        identity,
        lifecycle,
        relation,
        effective_uid: None,
    }
}

#[cfg(not(windows))]
fn observe_windows_process(_pid: u32) -> Observation {
    unavailable("Windows process identity inspection is unsupported on this host")
}

#[cfg(windows)]
enum ProcessError {
    Absent { reason: &'static str },
    Unavailable(String),
}

#[cfg(windows)]
fn process_creation_identity(pid: u32) -> Result<String, ProcessError> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // Query-only access is deliberate: identity observation does not grant
    // termination, suspension, or other process-control authority.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        return Err(match error {
            ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => ProcessError::Absent {
                reason: "not-found-in-caller-process-namespace",
            },
            ERROR_ACCESS_DENIED => {
                ProcessError::Unavailable("access denied while opening process identity".into())
            }
            _ => {
                ProcessError::Unavailable(format!("OpenProcess failed with Windows error {error}"))
            }
        });
    }

    let mut creation_time = std::mem::MaybeUninit::zeroed();
    let mut exit_time = std::mem::MaybeUninit::zeroed();
    let mut kernel_time = std::mem::MaybeUninit::zeroed();
    let mut user_time = std::mem::MaybeUninit::zeroed();
    let read = unsafe {
        GetProcessTimes(
            handle,
            creation_time.as_mut_ptr(),
            exit_time.as_mut_ptr(),
            kernel_time.as_mut_ptr(),
            user_time.as_mut_ptr(),
        )
    } != 0;
    let read_error = (!read).then(|| unsafe { GetLastError() });
    let closed = unsafe { CloseHandle(handle) } != 0;
    if !closed {
        return Err(ProcessError::Unavailable(format!(
            "CloseHandle failed with Windows error {}",
            unsafe { GetLastError() }
        )));
    }

    let Some(error) = read_error else {
        let creation_time = unsafe { creation_time.assume_init() };
        return Ok(format!(
            "windows-creation-time:{}",
            filetime_value(creation_time.dwHighDateTime, creation_time.dwLowDateTime)
        ));
    };

    if error == ERROR_ACCESS_DENIED {
        Err(ProcessError::Unavailable(
            "access denied while reading process identity".into(),
        ))
    } else {
        Err(ProcessError::Unavailable(format!(
            "GetProcessTimes failed with Windows error {error}"
        )))
    }
}

#[cfg(windows)]
fn process_lifecycle(pid: u32) -> Option<rea_core::linux_proc::stat::Lifecycle> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut exit_code = 0;
    let read = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
    let closed = unsafe { CloseHandle(handle) } != 0;
    if !read || !closed {
        return None;
    }

    const STILL_ACTIVE: u32 = 259;
    Some(lifecycle_from_exit_code(exit_code))
}

#[cfg(windows)]
fn lifecycle_from_exit_code(exit_code: u32) -> rea_core::linux_proc::stat::Lifecycle {
    const STILL_ACTIVE: u32 = 259;
    if exit_code == STILL_ACTIVE {
        rea_core::linux_proc::stat::Lifecycle::NonZombie
    } else {
        rea_core::linux_proc::stat::Lifecycle::Dead
    }
}

#[cfg(windows)]
fn stable_parent_relation(pid: u32) -> Option<Relation> {
    let first = parent_observation(pid)?;
    let first_identity = process_creation_identity(first).ok();
    let second = parent_observation(pid)?;
    let second_identity = process_creation_identity(second).ok();
    let mut relation = stable_parent_relation_from_snapshots(
        Some(first),
        first_identity,
        Some(second),
        second_identity,
    )?;
    relation.session_id = process_session_id(pid);
    Some(relation)
}

#[cfg(windows)]
fn stable_parent_relation_from_snapshots(
    first_parent: Option<u32>,
    first_identity: Option<String>,
    second_parent: Option<u32>,
    second_identity: Option<String>,
) -> Option<Relation> {
    let parent_generation_stable = match (&first_identity, &second_identity) {
        (Some(first), Some(second)) => first == second,
        _ => true,
    };
    if first_parent != second_parent || !parent_generation_stable {
        return None;
    }
    first_parent.map(|parent_pid| Relation {
        parent_pid: u64::from(parent_pid),
        process_group_id: None,
        session_id: None,
        parent_identity: first_identity,
    })
}

#[cfg(windows)]
fn parent_observation(pid: u32) -> Option<u32> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        let _ = unsafe { GetLastError() };
        return None;
    }
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut parent = None;
    let mut read = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while read {
        if entry.th32ProcessID == pid {
            parent = Some(entry.th32ParentProcessID);
            break;
        }
        read = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    let _ = unsafe { CloseHandle(snapshot) };
    parent
}

#[cfg(windows)]
fn process_session_id(pid: u32) -> Option<u64> {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session_id = 0;
    let read = unsafe { ProcessIdToSessionId(pid, &mut session_id) } != 0;
    read.then_some(u64::from(session_id))
}

#[cfg(windows)]
fn filetime_value(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

fn unavailable(reason: impl Into<String>) -> Observation {
    Observation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn observes_current_process_with_query_only_creation_identity() {
        let observation = WindowsProcessIdentityObserver.observe(std::process::id() as u64);
        let Observation::Readable {
            identity,
            relation,
            effective_uid,
            ..
        } = observation
        else {
            panic!("current process identity should be readable");
        };
        assert!(identity.starts_with("windows-creation-time:"));
        assert!(relation.is_some());
        assert!(effective_uid.is_none());
    }

    #[test]
    fn invalid_pid_is_unavailable_without_claiming_absence() {
        assert!(matches!(
            WindowsProcessIdentityObserver.observe(0),
            Observation::Unavailable { .. }
        ));
    }

    #[test]
    fn generation_revalidation_preserves_replacement_and_unknown() {
        let readable = |identity: &str| Observation::Readable {
            identity: identity.into(),
            lifecycle: None,
            relation: None,
            effective_uid: None,
        };
        let observer = WindowsProcessIdentityObserver;
        assert_eq!(
            observer.generation(&readable("a"), &readable("b")),
            Generation::Replaced
        );
        assert_eq!(
            observer.generation(
                &readable("a"),
                &Observation::Unavailable {
                    reason: "access denied".into()
                }
            ),
            Generation::Unavailable
        );
    }

    #[test]
    fn lifecycle_maps_exit_code_without_treating_reused_pid_as_alive() {
        use rea_core::linux_proc::stat::Lifecycle;

        assert_eq!(lifecycle_from_exit_code(259), Lifecycle::NonZombie);
        assert_eq!(lifecycle_from_exit_code(0), Lifecycle::Dead);
    }

    #[test]
    fn parent_pid_reuse_invalidates_relation_snapshot() {
        assert!(
            stable_parent_relation_from_snapshots(
                Some(41),
                Some("windows-creation-time:one".into()),
                Some(41),
                Some("windows-creation-time:two".into()),
            )
            .is_none()
        );
    }
}
