//! Read-only native process identity observations.
//!
//! This module deliberately stops at observation.  A readable start-time token
//! and native relation facts do not grant authority to signal or clean up a
//! process.  Callers must keep the before/after observations and interpret a
//! changed generation as unsafe to attribute.

use rea_core::linux_proc::stat::Lifecycle;
use std::collections::BTreeMap;

#[cfg(windows)]
use crate::process::windows::identity::WindowsProcessIdentityObserver as NativeWindowsProcessIdentityObserver;
#[cfg(target_os = "linux")]
use rea_core::linux_proc::stat::ParseError;
#[cfg(target_os = "linux")]
use std::{fs, io, io::Read, path::PathBuf};

#[cfg(target_os = "linux")]
const MAX_PROC_STAT_BYTES: usize = 64 * 1024;

/// Native relation facts read from the same `/proc/<pid>/stat` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relation {
    pub parent_pid: u64,
    pub process_group_id: Option<u64>,
    pub session_id: Option<u64>,
    pub parent_identity: Option<String>,
}

/// A bounded observation of one process identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observation {
    Readable {
        identity: String,
        lifecycle: Option<Lifecycle>,
        relation: Option<Relation>,
        effective_uid: Option<u64>,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

/// Result of comparing two observations for one PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Generation {
    Same,
    Replaced,
    Absent,
    Unavailable,
}

/// Read native process identity facts without process-control authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessIdentityObserver;

/// Compatibility name for callers that adopted the initial Linux-only API.
pub type LinuxProcessIdentityObserver = ProcessIdentityObserver;

/// Windows uses the same observer contract with creation-time identities.
pub type WindowsProcessIdentityObserver = ProcessIdentityObserver;

impl ProcessIdentityObserver {
    /// Observe one PID. A missing procfs record is reported as bounded absence;
    /// permission and malformed-record failures remain explicitly unavailable.
    pub fn observe(&self, pid: u64, include_effective_uid: bool) -> Observation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid, include_effective_uid)
    }

    /// Observe each requested PID without enumerating the process table.
    pub fn observe_many<I>(
        &self,
        pids: I,
        include_effective_uid: bool,
    ) -> BTreeMap<u64, Observation>
    where
        I: IntoIterator<Item = u64>,
    {
        pids.into_iter()
            .map(|pid| (pid, self.observe(pid, include_effective_uid)))
            .collect()
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn observe_platform(_pid: u64, _include_effective_uid: bool) -> Observation {
    unavailable("native process identity inspection is unsupported on this host")
}

#[cfg(target_os = "linux")]
fn observe_platform(pid: u64, include_effective_uid: bool) -> Observation {
    let stat_path = proc_path(pid, "stat");
    let stat = match read_bounded_proc_text(&stat_path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Observation::Absent {
                reason: "not-found-in-caller-pid-namespace",
            };
        }
        Err(error) => return unavailable(format_io("read proc stat", &stat_path, error)),
    };
    let facts = match rea_core::linux_proc::stat::parse(&stat) {
        Ok(facts) if facts.pid == pid => facts,
        Ok(_) => return unavailable("proc stat PID did not match requested PID"),
        Err(error) => return unavailable(format_parse(&stat_path, error)),
    };
    let identity = format!("linux-starttime:{}", facts.start_time);
    let effective_uid = if !include_effective_uid {
        None
    } else {
        let status_uid = read_effective_uid(pid);
        let verified_identity = read_linux_identity(pid);
        match merge_effective_uid(&identity, status_uid, verified_identity.as_deref()) {
            Ok(uid) => uid,
            Err(observation) => return observation,
        }
    };
    let parent_identity = read_linux_identity(facts.parent_pid);
    readable_linux_facts(identity, facts, effective_uid, parent_identity)
}

#[cfg(target_os = "linux")]
fn readable_linux_facts(
    identity: String,
    facts: rea_core::linux_proc::stat::ProcessStat<'_>,
    effective_uid: Option<u64>,
    parent_identity: Option<String>,
) -> Observation {
    Observation::Readable {
        identity,
        lifecycle: facts.lifecycle,
        relation: Some(Relation {
            parent_pid: facts.parent_pid,
            process_group_id: Some(facts.process_group_id),
            session_id: Some(facts.session_id),
            parent_identity,
        }),
        effective_uid,
    }
}

#[cfg(target_os = "linux")]
fn read_linux_identity(pid: u64) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let path = proc_path(pid, "stat");
    let stat = read_bounded_proc_text(&path).ok()?;
    let facts = rea_core::linux_proc::stat::parse(&stat).ok()?;
    (facts.pid == pid).then(|| format!("linux-starttime:{}", facts.start_time))
}

#[cfg(target_os = "linux")]
fn merge_effective_uid(
    initial_identity: &str,
    status_uid: Result<u64, String>,
    verified_identity: Option<&str>,
) -> Result<Option<u64>, Observation> {
    let Ok(uid) = status_uid else {
        return Ok(None);
    };
    if verified_identity != Some(initial_identity) {
        return Err(unavailable(
            "process identity changed during uid observation",
        ));
    }
    Ok(Some(uid))
}

#[cfg(windows)]
fn observe_platform(pid: u64, _include_effective_uid: bool) -> Observation {
    NativeWindowsProcessIdentityObserver.observe(pid)
}

#[cfg(target_os = "macos")]
fn observe_platform(pid: u64, _include_effective_uid: bool) -> Observation {
    use std::mem::size_of;

    let Ok(process_id) = libc::pid_t::try_from(pid) else {
        return unavailable("process id is outside the macOS PID range");
    };
    let mut facts = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: PROC_PIDTBSDINFO is a read-only query; the initialized output
    // buffer and its exact size are passed to the Darwin API.
    let result = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDTBSDINFO,
            0,
            facts.as_mut_ptr().cast(),
            size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if result <= 0 {
        // SAFETY: __error returns Darwin's thread-local errno slot.
        let error = unsafe { *libc::__error() };
        return macos_identity_error(error);
    }
    if result as usize != size_of::<libc::proc_bsdinfo>() {
        return unavailable(format!(
            "proc_pidinfo returned {result} bytes, expected {}",
            size_of::<libc::proc_bsdinfo>()
        ));
    }

    // SAFETY: proc_pidinfo reported the complete structure size above.
    let facts = unsafe { facts.assume_init() };
    let lifecycle = if facts.pbi_status == 5 {
        Lifecycle::Zombie
    } else {
        Lifecycle::NonZombie
    };
    Observation::Readable {
        identity: format!("{}:{}", facts.pbi_start_tvsec, facts.pbi_start_tvusec),
        lifecycle: Some(lifecycle),
        relation: Some(Relation {
            parent_pid: u64::from(facts.pbi_ppid),
            process_group_id: Some(u64::from(facts.pbi_pgid)),
            session_id: None,
            parent_identity: read_macos_identity(facts.pbi_ppid),
        }),
        effective_uid: Some(u64::from(facts.pbi_uid)),
    }
}

#[cfg(target_os = "macos")]
fn macos_identity_error(error: i32) -> Observation {
    if error == libc::ESRCH {
        Observation::Absent {
            reason: "not-found-in-caller-process-namespace",
        }
    } else {
        unavailable(format!("proc_pidinfo failed with Darwin error {error}"))
    }
}

#[cfg(target_os = "macos")]
fn read_macos_identity(pid: u32) -> Option<String> {
    use std::mem::size_of;

    if pid == 0 {
        return None;
    }
    let mut facts = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: This is a bounded read-only query into an initialized buffer.
    let result = unsafe {
        libc::proc_pidinfo(
            libc::pid_t::try_from(pid).ok()?,
            libc::PROC_PIDTBSDINFO,
            0,
            facts.as_mut_ptr().cast(),
            size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if result as usize != size_of::<libc::proc_bsdinfo>() {
        return None;
    }
    // SAFETY: The API reported exactly the structure size above.
    let facts = unsafe { facts.assume_init() };
    Some(format!(
        "{}:{}",
        facts.pbi_start_tvsec, facts.pbi_start_tvusec
    ))
}

#[cfg(windows)]
fn filetime_value(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

/// Compare before/after identity reads while preserving absent and unknown states.
pub fn generation(before: &Observation, after: &Observation) -> Generation {
    match after {
        Observation::Absent { .. } => Generation::Absent,
        Observation::Readable { identity, .. } => match before {
            Observation::Readable {
                identity: previous, ..
            } if previous == identity => Generation::Same,
            Observation::Readable { .. } | Observation::Absent { .. } => Generation::Replaced,
            Observation::Unavailable { .. } => Generation::Unavailable,
        },
        Observation::Unavailable { .. } => Generation::Unavailable,
    }
}

#[cfg(target_os = "linux")]
fn proc_path(pid: u64, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{name}"))
}

#[cfg(target_os = "linux")]
fn read_effective_uid(pid: u64) -> Result<u64, String> {
    let path = proc_path(pid, "status");
    let text =
        fs::read_to_string(&path).map_err(|error| format_io("read proc status", &path, error))?;
    rea_core::linux_proc::status::effective_uid(&text).map_err(|error| format!("{path:?}: {error}"))
}

#[cfg(target_os = "linux")]
fn read_bounded_proc_text(path: &PathBuf) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_PROC_STAT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROC_STAT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc stat record exceeds observation bound",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn unavailable(reason: impl Into<String>) -> Observation {
    Observation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn format_io(stage: &str, path: &PathBuf, error: io::Error) -> String {
    format!("{stage} {path:?}: {error}")
}

#[cfg(target_os = "linux")]
fn format_parse(path: &PathBuf, error: ParseError) -> String {
    format!("{path:?}: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readable(identity: &str) -> Observation {
        Observation::Readable {
            identity: identity.to_owned(),
            lifecycle: None,
            relation: Some(Relation {
                parent_pid: 1,
                process_group_id: Some(2),
                session_id: Some(3),
                parent_identity: None,
            }),
            effective_uid: None,
        }
    }

    #[test]
    fn generation_preserves_same_replaced_absent_and_unknown() {
        assert_eq!(generation(&readable("a"), &readable("a")), Generation::Same);
        assert_eq!(
            generation(&readable("a"), &readable("b")),
            Generation::Replaced
        );
        assert_eq!(
            generation(&readable("a"), &Observation::Absent { reason: "gone" }),
            Generation::Absent
        );
        assert_eq!(
            generation(
                &Observation::Unavailable {
                    reason: "before".into()
                },
                &readable("a")
            ),
            Generation::Unavailable
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uid_enrichment_is_discarded_when_status_is_unavailable_or_malformed() {
        assert_eq!(
            merge_effective_uid(
                "linux-starttime:10",
                Err("status unreadable".into()),
                Some("linux-starttime:10")
            )
            .expect("status failure should not invalidate the base identity"),
            None
        );
        assert_eq!(
            merge_effective_uid(
                "linux-starttime:10",
                Err("malformed status".into()),
                Some("linux-starttime:10")
            )
            .expect("malformed status should not invalidate the base identity"),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uid_enrichment_rejects_a_changed_process_generation() {
        let result =
            merge_effective_uid("linux-starttime:10", Ok(1000), Some("linux-starttime:11"));
        assert!(matches!(
            result,
            Err(Observation::Unavailable { reason })
                if reason == "process identity changed during uid observation"
        ));
    }

    #[test]
    fn invalid_pid_is_unavailable_without_claiming_absence() {
        assert!(matches!(
            ProcessIdentityObserver.observe(0, false),
            Observation::Unavailable { .. }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_stat_reader_rejects_records_over_the_observation_bound() {
        let temporary = tempfile::NamedTempFile::new().expect("temporary proc fixture");
        let oversized = vec![b'x'; MAX_PROC_STAT_BYTES + 1];
        std::fs::write(temporary.path(), oversized).expect("write oversized proc fixture");

        let error = read_bounded_proc_text(&temporary.path().to_path_buf())
            .expect_err("oversized proc fixture must remain unavailable");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observes_current_process_with_start_identity_and_relation() {
        let observation = ProcessIdentityObserver.observe(std::process::id() as u64, true);
        let Observation::Readable {
            identity,
            relation,
            effective_uid,
            ..
        } = observation
        else {
            panic!("current process identity was not readable");
        };
        assert!(identity.starts_with("linux-starttime:"));
        let relation = relation.expect("Linux observations include relation facts");
        assert!(relation.session_id.expect("Linux session ID is observed") > 0);
        assert!(relation.parent_identity.is_some());
        assert!(effective_uid.is_some());
    }

    #[cfg(windows)]
    #[test]
    fn observes_current_process_with_creation_identity() {
        let observation = ProcessIdentityObserver.observe(std::process::id() as u64, false);
        let Observation::Readable {
            identity,
            lifecycle,
            relation,
            effective_uid,
        } = observation
        else {
            panic!("current process identity was not readable");
        };
        assert!(identity.starts_with("windows-creation-time:"));
        assert_eq!(lifecycle, Some(Lifecycle::NonZombie));
        let relation = relation.expect("Windows observations include parent relation facts");
        assert!(relation.parent_pid > 0);
        assert!(relation.parent_identity.is_some());
        assert!(relation.process_group_id.is_none());
        assert!(relation.session_id.is_some());
        assert!(effective_uid.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn observes_current_process_with_start_identity_and_relations() {
        let observation = ProcessIdentityObserver.observe(std::process::id() as u64, false);
        let Observation::Readable {
            identity,
            lifecycle,
            relation,
            effective_uid,
        } = observation
        else {
            panic!("current process identity was not readable");
        };
        assert!(identity.contains(':'));
        assert!(lifecycle.is_some());
        let relation = relation.expect("macOS observations include relation facts");
        assert!(relation.parent_pid > 0);
        assert!(relation.parent_identity.is_some());
        assert!(relation.session_id.is_none());
        assert!(effective_uid.is_some());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classifies_darwin_missing_identity_as_absent() {
        assert!(matches!(
            macos_identity_error(libc::ESRCH),
            Observation::Absent {
                reason: "not-found-in-caller-process-namespace"
            }
        ));
        assert!(matches!(
            macos_identity_error(libc::EPERM),
            Observation::Unavailable { reason }
                if reason == "proc_pidinfo failed with Darwin error 1"
        ));
    }
}
