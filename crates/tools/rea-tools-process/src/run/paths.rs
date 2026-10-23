//! Runtime path resolution, launch environment and executable sampling.
//!
//! Compatibility owners: `resolveProcessScenarioRuntimePaths` and
//! `resolveExecutable` (`ProcessScenarioRuntimeValidation.ts`),
//! `makeProcessCaptureEnvironment` (`ProcessCaptureEnvironment.ts`), and
//! `observeSelectedExecutable` / `observeLaunchedExecutable`
//! (`ProcessCaptureLifecycle.ts`).

use super::scenario::Scenario;
use super::snapshot::system_code;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const OPERATION: &str = "capture_process_scenario";

fn invalid(field: &str, message: String) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue {
            path: vec![json!(field)],
            reason: "invalid_value",
            message: Some(message),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}

fn os_failure(error: &io::Error) -> String {
    system_code(error).map(|code| format!(" ({code})")).unwrap_or_default()
}

/// Node `path.resolve(base, path)`: lexical, `.`/`..` collapsed, no symlinks.
pub fn resolve(base: &Path, path: &str) -> PathBuf {
    let joined = if Path::new(path).is_absolute() { PathBuf::from(path) } else { base.join(path) };
    let mut out = PathBuf::from("/");
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
            _ => {}
        }
    }
    out
}

/// `access(X_OK)` for the effective user.
fn executable_access(path: &Path) -> io::Result<()> {
    rustix::fs::access(path, rustix::fs::Access::EXEC_OK).map_err(io::Error::from)
}

/// `resolveExecutable`.
pub fn resolve_executable(command: &str, working_directory: &Path, search_path: &str) -> Result<String, AnalysisError> {
    let candidates: Vec<PathBuf> = if command.starts_with('/') || command.contains('/') {
        vec![resolve(working_directory, command)]
    } else {
        search_path
            .split(':')
            .map(|directory| if directory.is_empty() { working_directory.to_path_buf() } else { resolve(working_directory, directory) })
            .map(|directory| resolve(&directory, command))
            .collect()
    };
    let mut failures = Vec::new();
    for candidate in candidates {
        let display = candidate.to_string_lossy().into_owned();
        match executable_access(&candidate).and_then(|()| fs::metadata(&candidate)) {
            Ok(stats) if stats.is_file() => return Ok(display),
            Ok(_) => failures.push(format!("{display} (not a regular file)")),
            Err(error) => failures.push(format!("{display}{}", os_failure(&error))),
        }
    }
    Err(invalid("executable", format!("executable could not be resolved: {command}; checked {}", failures.join("; "))))
}

/// `resolveProcessScenarioRuntimePaths`.
pub fn resolve_runtime_paths(scenario: &Scenario, host: &HashMap<String, String>) -> Result<Scenario, AnalysisError> {
    // `path.resolve` is relative to the server's working directory.
    let process_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let selected = resolve(&process_cwd, &scenario.working_directory);
    let working_directory = fs::canonicalize(&selected).map_err(|error| {
        invalid("working_directory", format!("working directory could not be resolved: {}{}", selected.display(), os_failure(&error)))
    })?;
    let stats = fs::metadata(&working_directory).map_err(|error| {
        invalid("working_directory", format!("working directory could not be inspected: {}{}", working_directory.display(), os_failure(&error)))
    })?;
    if !stats.is_dir() {
        return Err(invalid("working_directory", format!("working directory is not a directory: {}", working_directory.display())));
    }
    let scenario_path = scenario.environment.iter().find(|(key, _)| key == "PATH").map(|(_, value)| value.clone());
    let search_path = scenario_path.or_else(|| host.get("PATH").cloned()).unwrap_or_default();
    let executable = resolve_executable(&scenario.executable, &working_directory, &search_path)?;
    let observation_paths = scenario
        .filesystem_observation_paths
        .iter()
        .map(|path| resolve(&working_directory, path).to_string_lossy().into_owned())
        .collect();
    Ok(scenario.with_resolved_paths(executable, working_directory.to_string_lossy().into_owned(), observation_paths))
}

/// `makeProcessCaptureEnvironment`: host, then caller overrides, then TERM and the run token.
pub fn capture_environment(scenario: &Scenario, host: &HashMap<String, String>, run_id: &str) -> Vec<(String, String)> {
    let mut environment: Vec<(String, String)> = host.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
    environment.sort();
    let mut set = |key: &str, value: String| match environment.iter_mut().find(|(existing, _)| existing == key) {
        Some(entry) => entry.1 = value,
        None => environment.push((key.to_owned(), value)),
    };
    for (key, value) in &scenario.environment {
        set(key, value.clone());
    }
    let term = scenario
        .environment
        .iter()
        .find(|(key, _)| key == "TERM")
        .map(|(_, value)| value.clone())
        .or_else(|| host.get("TERM").cloned())
        .unwrap_or_else(|| "xterm-256color".to_owned());
    set("TERM", term);
    set("REA_PROCESS_RUN_ID", run_id.to_owned());
    environment
}

/// Launch-time file identity (dev, ino, mode, size, mtime ns, ctime ns).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdentity([i128; 6]);

fn identity(stats: &Metadata) -> FileIdentity {
    let ns = |seconds: i64, nanos: i64| i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    FileIdentity([
        i128::from(stats.dev()),
        i128::from(stats.ino()),
        i128::from(stats.mode()),
        i128::from(stats.size()),
        ns(stats.mtime(), stats.mtime_nsec()),
        ns(stats.ctime(), stats.ctime_nsec()),
    ])
}

/// `SelectedExecutableObservation`.
pub struct SelectedExecutable {
    pub sha256: Option<String>,
    pub identity: Option<FileIdentity>,
    pub reason: Option<String>,
}

/// `LaunchedExecutableObservation`.
pub struct LaunchedExecutable {
    pub selected_sha256: Option<String>,
    pub sha256: Option<String>,
    pub state: &'static str,
    pub reason: Option<String>,
}

fn filesystem_failure(error: &io::Error) -> String {
    format!("Executable file observation failed: {error}")
}

/// `observeSelectedExecutable`.
pub fn observe_selected_executable(path: &str) -> SelectedExecutable {
    let failed = |reason: String| SelectedExecutable { sha256: None, identity: None, reason: Some(reason) };
    let mut file = match fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(error) => return failed(filesystem_failure(&error)),
    };
    let opened = match file.metadata() {
        Ok(stats) => stats,
        Err(error) => return failed(filesystem_failure(&error)),
    };
    if !opened.is_file() {
        return failed("Selected executable is not a regular file.".to_owned());
    }
    let opened_identity = identity(&opened);
    match fs::metadata(path) {
        Ok(stats) if identity(&stats) == opened_identity => {}
        Ok(_) => return failed("Selected executable path changed while it was being opened.".to_owned()),
        Err(error) => return failed(filesystem_failure(&error)),
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hash.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return failed(filesystem_failure(&error)),
        }
    }
    match file.metadata() {
        Ok(stats) if identity(&stats) == opened_identity => {}
        Ok(_) => return failed("Selected executable changed while its contents were sampled.".to_owned()),
        Err(error) => return failed(filesystem_failure(&error)),
    }
    let _ = opened.permissions().mode();
    SelectedExecutable {
        sha256: Some(format!("{:x}", hash.finalize())),
        identity: Some(opened_identity),
        reason: None,
    }
}

/// `observeLaunchedExecutable`.
pub fn observe_launched_executable(path: &str, selected: &SelectedExecutable) -> LaunchedExecutable {
    let (Some(expected), Some(sha256)) = (&selected.identity, &selected.sha256) else {
        return LaunchedExecutable {
            selected_sha256: selected.sha256.clone(),
            sha256: None,
            state: "unknown",
            reason: Some(selected.reason.clone().unwrap_or_else(|| "Selected executable identity is unavailable.".to_owned())),
        };
    };
    match fs::metadata(path) {
        Ok(stats) if stats.is_file() && identity(&stats) == *expected => LaunchedExecutable {
            selected_sha256: Some(sha256.clone()),
            sha256: Some(sha256.clone()),
            state: "path_metadata_unchanged",
            reason: None,
        },
        Ok(_) => LaunchedExecutable {
            selected_sha256: Some(sha256.clone()),
            sha256: None,
            state: "unknown",
            reason: Some("Executable path metadata changed between sampling and spawn.".to_owned()),
        },
        Err(error) => LaunchedExecutable {
            selected_sha256: Some(sha256.clone()),
            sha256: None,
            state: "unknown",
            reason: Some(filesystem_failure(&error)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_like_node_path_resolve() {
        assert_eq!(resolve(Path::new("/a/b"), "../c/./d"), PathBuf::from("/a/c/d"));
        assert_eq!(resolve(Path::new("/a"), "/x/../y"), PathBuf::from("/y"));
    }

    #[test]
    fn reports_every_checked_candidate() {
        let error = resolve_executable("no-such-tool-rea", Path::new("/tmp"), "/usr/bin:/bin").unwrap_err();
        let text = format!("{error:?}");
        assert!(text.contains("checked /usr/bin/no-such-tool-rea (ENOENT); /bin/no-such-tool-rea (ENOENT)"), "{text}");
        assert_eq!(resolve_executable("sh", Path::new("/tmp"), "/usr/bin:/bin").unwrap(), "/bin/sh");
    }

    #[test]
    fn caller_environment_overrides_host_and_run_token_is_last() {
        let scenario = Scenario::from_input(&json!({
            "executable": "/bin/echo", "arguments": [], "working_directory": ".", "environment": {"A": "caller"},
            "filesystem_observation_paths": [], "terminal": {"columns": 80, "rows": 24, "scrollback": 0}, "events": [],
            "timeout_ms": 1, "idle_timeout_ms": 1, "settle_ms": 0, "finalization_ms": 0,
            "limits": {"output_bytes": 1, "files": 1, "file_bytes": 1, "processes": 1, "filesystem_depth": 0},
            "normalization": {"paths": false, "pids": true, "ports": true, "time_bucket_ms": 10, "patterns": []},
        }));
        let host = HashMap::from([("A".to_owned(), "host".to_owned()), ("TERM".to_owned(), "dumb".to_owned())]);
        let environment = capture_environment(&scenario, &host, "run-1");
        assert!(environment.contains(&("A".to_owned(), "caller".to_owned())));
        assert!(environment.contains(&("TERM".to_owned(), "dumb".to_owned())));
        assert_eq!(environment.last().unwrap(), &("REA_PROCESS_RUN_ID".to_owned(), "run-1".to_owned()));
    }
}
