//! Bounded observation of the caller-owned process run token.

#[cfg(target_os = "linux")]
use std::{fs, io, io::Read, path::PathBuf};

pub const MAX_PROC_ENVIRONMENT_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunTokenObservation {
    Readable { run_id: Option<String> },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessRunTokenObserver;

impl ProcessRunTokenObserver {
    pub fn observe(&self, pid: u64) -> RunTokenObservation {
        if pid == 0 {
            return unavailable("process id must be positive");
        }
        observe_platform(pid)
    }
}

#[cfg(target_os = "linux")]
fn observe_platform(pid: u64) -> RunTokenObservation {
    let path = PathBuf::from(format!("/proc/{pid}/environ"));
    let bytes = match read_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return RunTokenObservation::Absent {
                reason: "not-found-in-caller-pid-namespace",
            };
        }
        Err(error) => return unavailable(format!("read proc environment {path:?}: {error}")),
    };
    let entries: Vec<_> = bytes.split(|byte| *byte == 0).collect();
    let run_id = match extract_run_id(&entries) {
        Ok(run_id) => run_id,
        Err(reason) => return unavailable(reason),
    };
    RunTokenObservation::Readable { run_id }
}

#[cfg(target_os = "macos")]
fn observe_platform(pid: u64) -> RunTokenObservation {
    use crate::process::macos::run_token::{DarwinRunToken, read_run_token};
    let Ok(pid) = i32::try_from(pid) else {
        return unavailable("process id is outside the macOS PID range");
    };
    match read_run_token(pid) {
        DarwinRunToken::Readable { run_id } => RunTokenObservation::Readable { run_id },
        DarwinRunToken::Unavailable { reason } => unavailable(reason),
    }
}

#[cfg(target_os = "windows")]
fn observe_platform(_pid: u64) -> RunTokenObservation {
    // Windows has no read-only public API for another process's environment.
    // Keep the fact explicitly unavailable instead of invoking a shell or
    // treating the observer's own environment as the target's environment.
    unavailable("Windows target environment query is unavailable")
}

#[cfg(all(
    not(target_os = "linux"),
    not(target_os = "macos"),
    not(target_os = "windows")
))]
fn observe_platform(_pid: u64) -> RunTokenObservation {
    unavailable("Linux proc environment observation is unsupported on this host")
}

fn unavailable(reason: impl Into<String>) -> RunTokenObservation {
    RunTokenObservation::Unavailable {
        reason: reason.into(),
    }
}

#[cfg(target_os = "linux")]
fn extract_run_id(entries: &[&[u8]]) -> Result<Option<String>, &'static str> {
    let mut run_id = None;
    for entry in entries {
        let Some(value) = entry.strip_prefix(b"REA_PROCESS_RUN_ID=") else {
            continue;
        };
        if run_id.is_some() {
            return Err("duplicate run token");
        }
        let Ok(value) = std::str::from_utf8(value) else {
            return Err("invalid run token encoding");
        };
        if value.is_empty() {
            return Err("invalid empty run token");
        }
        run_id = Some(value.to_owned());
    }
    Ok(run_id)
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &PathBuf) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_PROC_ENVIRONMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROC_ENVIRONMENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc environment exceeds observation bound",
        ));
    }
    Ok(bytes)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn observes_only_the_run_token_key() {
        let bytes = b"SECRET=hidden\0REA_PROCESS_RUN_ID=run-7\0OTHER=value\0";
        let entries: Vec<_> = bytes.split(|byte| *byte == 0).collect();
        assert_eq!(extract_run_id(&entries).unwrap().as_deref(), Some("run-7"));
    }

    #[test]
    fn rejects_duplicate_or_malformed_tokens() {
        assert_eq!(
            extract_run_id(&[b"REA_PROCESS_RUN_ID=one", b"REA_PROCESS_RUN_ID=two"]),
            Err("duplicate run token")
        );
        assert_eq!(
            extract_run_id(&[b"REA_PROCESS_RUN_ID=\xff"]),
            Err("invalid run token encoding")
        );
    }
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod windows_tests {
    use super::*;

    #[test]
    fn invalid_pid_remains_unavailable_without_target_query() {
        assert!(matches!(
            ProcessRunTokenObserver.observe(0),
            RunTokenObservation::Unavailable { reason } if reason == "process id must be positive"
        ));
    }
}
