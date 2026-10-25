//! Native package-manager update workflow.
//!
//! This module owns the update transaction after the CLI has selected the
//! operation.  Installation identity is established before any mutating
//! command is launched; registry output and post-install verification are
//! bounded and cancellation remains observable throughout child settlement.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use rea_core::cancellation::Cancellation;
use rea_host::process::launcher::{ChildExit, ChildLaunchSpec, ChildOutput, OwnedChildProcess};
use rea_host::process::windows::job::WindowsJobLimits;
use serde_json::{Value, json};

use crate::update_runtime::{
    PACKAGE_NAME, UPDATE_COMMAND_OUTPUT_BYTES, UpdateInstallation, bun_global_directory,
    detect_bun_installation, detect_npm_installation, npm_latest_command, parse_npm_latest_version,
    update_install_command,
};

const MAX_VERSION_OUTPUT_BYTES: usize = 64 * 1024;

/// Run the native update workflow using the package root that owns this
/// executable.  The caller supplies an explicit environment so tests and
/// adapters never accidentally persist or reinterpret ambient state.
pub fn run_update(
    current_version: &str,
    package_root: &Path,
    environment: &BTreeMap<String, String>,
    cancellation: &Cancellation,
) -> Value {
    run_update_with_maintenance(
        current_version,
        package_root,
        environment,
        cancellation,
        |_| {
            json!({
                "status": "unavailable",
                "remediation": "The update was verified. Review existing integrations with rea setup before restarting agents.",
            })
        },
    )
}

/// Run an update and let the application owner supply its read-only
/// integration-maintenance planner after executable verification succeeds.
pub fn run_update_with_maintenance<F>(
    current_version: &str,
    package_root: &Path,
    environment: &BTreeMap<String, String>,
    cancellation: &Cancellation,
    maintenance: F,
) -> Value
where
    F: Fn(&UpdateInstallation) -> Value,
{
    let result = UpdateWorkflow::new(
        current_version,
        package_root,
        environment,
        cancellation,
        true,
    )
    .with_maintenance(&maintenance)
    .run();
    match result {
        Ok(value) => value,
        Err(error) => json!({
            "status": "failed",
            "reason": error.kind,
            "currentVersion": current_version,
            "latestVersion": error.latest_version,
            "remediation": error.remediation,
        }),
    }
}

/// The update-check form intentionally performs no installation mutation.
pub fn run_update_check(
    current_version: &str,
    package_root: &Path,
    environment: &BTreeMap<String, String>,
    cancellation: &Cancellation,
) -> Value {
    let result = UpdateWorkflow::new(
        current_version,
        package_root,
        environment,
        cancellation,
        false,
    )
    .run();
    match result {
        Ok(value) => value,
        Err(error) => json!({
            "status": "failed",
            "reason": error.kind,
            "currentVersion": current_version,
            "latestVersion": error.latest_version,
            "remediation": error.remediation,
        }),
    }
}

struct UpdateWorkflow<'a> {
    current_version: &'a str,
    package_root: &'a Path,
    environment: &'a BTreeMap<String, String>,
    cancellation: &'a Cancellation,
    allow_install: bool,
    maintenance: Option<&'a dyn Fn(&UpdateInstallation) -> Value>,
}

impl<'a> UpdateWorkflow<'a> {
    fn new(
        current_version: &'a str,
        package_root: &'a Path,
        environment: &'a BTreeMap<String, String>,
        cancellation: &'a Cancellation,
        allow_install: bool,
    ) -> Self {
        Self {
            current_version,
            package_root,
            environment,
            cancellation,
            allow_install,
            maintenance: None,
        }
    }

    fn with_maintenance(mut self, maintenance: &'a dyn Fn(&UpdateInstallation) -> Value) -> Self {
        self.maintenance = Some(maintenance);
        self
    }

    fn run(&self) -> Result<Value, UpdateError> {
        self.ensure_active()?;
        let installation = self.identify_installation();
        let latest = self.latest_version(installation.as_ref())?;
        let current = Version::parse(self.current_version).ok_or_else(|| {
            UpdateError::version_check("the current executable version is not a valid semver")
        })?;
        let target = Version::parse(&latest).ok_or_else(|| {
            UpdateError::version_check("the package registry returned invalid version metadata")
        })?;
        if target <= current {
            return Ok(json!({
                "status": "current",
                "currentVersion": self.current_version,
                "latestVersion": target.to_string(),
                "installMethod": installation.as_ref().map(UpdateInstallation::manager_name).unwrap_or("unknown"),
            }));
        }
        if !self.allow_install {
            return Ok(json!({
                "status": "available",
                "currentVersion": self.current_version,
                "latestVersion": target.to_string(),
                "installMethod": installation.as_ref().map(UpdateInstallation::manager_name).unwrap_or("unknown"),
            }));
        }

        let Some(installation) = installation else {
            return Err(UpdateError::unknown_installation(
                "Update this installation with the package manager or source checkout that owns it. For a one-off latest invocation, use npx rea-agents@latest.",
                Some(target.to_string()),
            ));
        };

        self.ensure_active()?;
        let command = update_install_command(&installation, &target.to_string());
        self.run_command(
            &command,
            installation_working_directory(&installation),
            UPDATE_COMMAND_OUTPUT_BYTES,
            false,
        )
        .map_err(|error| UpdateError::from_command(error, Some(target.to_string()), "install"))?;
        self.ensure_active()?;

        let verified_command = vec![
            self.environment
                .get("REA_NODE")
                .cloned()
                .unwrap_or_else(|| "node".into()),
            installation
                .package_root()
                .join("scripts")
                .join("rea.mjs")
                .to_string_lossy()
                .into_owned(),
            "--version".into(),
        ];
        let verified = self
            .run_command(&verified_command, None, MAX_VERSION_OUTPUT_BYTES, true)
            .map_err(|error| {
                UpdateError::from_command(error, Some(target.to_string()), "verification")
            })?;
        let installed = Version::parse(verified.trim()).ok_or_else(|| {
            UpdateError::verification(
                "the updated executable returned invalid version metadata",
                Some(target.to_string()),
            )
        })?;
        if installed != target {
            return Err(UpdateError::verification(
                format!(
                    "the executable reported {} after installing {}",
                    installed, target
                ),
                Some(target.to_string()),
            ));
        }

        let maintenance = self.maintenance.map(|planner| planner(&installation)).unwrap_or_else(|| json!({
            "status": "unavailable",
            "remediation": "The update was verified. Review existing integrations with rea setup before restarting agents.",
        }));
        let status = if maintenance.get("status").and_then(Value::as_str) == Some("unavailable") {
            "deferred"
        } else {
            "updated"
        };
        Ok(json!({
            "status": status,
            "previousVersion": self.current_version,
            "latestVersion": target.to_string(),
            "installedVersion": installed.to_string(),
            "installMethod": installation.manager_name(),
            "command": command,
            "maintenance": maintenance,
            "remediation": "REA is updated. Review existing integrations with rea setup, then restart affected agents.",
        }))
    }

    fn identify_installation(&self) -> Option<UpdateInstallation> {
        let bun_directory = bun_global_directory(
            self.environment,
            Path::new("."),
            Path::new(
                self.environment
                    .get("HOME")
                    .map(String::as_str)
                    .unwrap_or("/"),
            ),
        );
        if let Some(installation) =
            detect_bun_installation(self.package_root, &bun_directory, &FsHost)
        {
            return Some(installation);
        }
        detect_npm_installation(
            self.package_root,
            &NpmHost {
                environment: self.environment,
                cancellation: self.cancellation,
            },
        )
    }

    fn latest_version(
        &self,
        installation: Option<&UpdateInstallation>,
    ) -> Result<String, UpdateError> {
        let command = match installation {
            Some(UpdateInstallation::Bun { .. }) => vec![
                "bun".into(),
                "info".into(),
                PACKAGE_NAME.into(),
                "dist-tags.latest".into(),
                "--json".into(),
            ],
            _ => npm_latest_command(installation),
        };
        if matches!(installation, Some(UpdateInstallation::Bun { .. })) {
            let bun_version = self
                .run_command(
                    &["bun".into(), "--version".into()],
                    installation_working_directory_opt(installation),
                    MAX_VERSION_OUTPUT_BYTES,
                    true,
                )
                .map_err(|error| UpdateError::from_command(error, None, "version-check"))?;
            let minimum = Version::parse("1.2.17").expect("valid bundled minimum Bun version");
            if Version::parse(bun_version.trim()).is_none_or(|version| version < minimum) {
                return Err(UpdateError {
                    kind: "version-check",
                    latest_version: None,
                    remediation: format!(
                        "REA updates for Bun global installations require Bun 1.2.17 or later; bun --version returned {:?}. Upgrade Bun manually, then rerun rea update.",
                        bun_version.trim()
                    ),
                });
            }
        }
        let output = self
            .run_command(
                &command,
                installation_working_directory_opt(installation),
                MAX_VERSION_OUTPUT_BYTES,
                true,
            )
            .map_err(|error| UpdateError::from_command(error, None, "version-check"))?;
        parse_npm_latest_version(output.trim()).map_err(UpdateError::version_check)
    }

    fn run_command(
        &self,
        command: &[String],
        working_directory: Option<PathBuf>,
        limit: usize,
        complete_output: bool,
    ) -> Result<String, CommandFailure> {
        self.ensure_active()
            .map_err(|error| CommandFailure::cancelled(error.remediation))?;
        let Some((executable, arguments)) = command.split_first() else {
            return Err(CommandFailure::ordinary("no executable supplied"));
        };
        let spec = ChildLaunchSpec {
            executable: PathBuf::from(executable),
            arguments: ChildLaunchSpec::arguments(arguments.iter().map(String::as_str)),
            working_directory,
            protocol_stdin: false,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        };
        let mut child = OwnedChildProcess::launch_with_environment(
            spec,
            &environment_pairs(self.environment),
            limit,
        )
        .map_err(|error| CommandFailure::ordinary(error.to_string()))?;
        let completed = settle_command_child(&mut child, self.cancellation, limit)?;
        let output = completed.output;
        if output.output_incomplete && !streams_closed(&output) {
            return Err(CommandFailure::ordinary(
                "update command did not settle its output streams before the retention deadline",
            ));
        }
        if output.output_incomplete && complete_output {
            return Err(CommandFailure::ordinary(format!(
                "update command output exceeded the {limit}-byte retention budget"
            )));
        }
        if completed.exit.code != 0 {
            let mut message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if output.output_incomplete {
                message.push_str(&format!(
                    "\n[Update diagnostics truncated at {limit} bytes; later output omitted.]"
                ));
            }
            return Err(CommandFailure::ordinary(message));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| CommandFailure::ordinary("update command returned invalid UTF-8"))
    }

    fn ensure_active(&self) -> Result<(), UpdateError> {
        self.cancellation.reason().map_or(Ok(()), |reason| {
            Err(UpdateError::cancelled(reason.to_owned()))
        })
    }
}

struct SettledCommand {
    exit: ChildExit,
    output: ChildOutput,
}

fn settle_command_child(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
    capture_limit: usize,
) -> Result<SettledCommand, CommandFailure> {
    let (_observed_exit, polled_output) =
        poll_child_until_exit(child, cancellation, capture_limit)?;
    let (exit, output) = finalize_child_output(child, cancellation, polled_output, capture_limit)?;
    Ok(SettledCommand { exit, output })
}

#[cfg(windows)]
fn merge_captured_output(destination: &mut ChildOutput, source: ChildOutput, limit: usize) {
    let total_remaining = limit.saturating_sub(
        destination
            .stdout
            .len()
            .saturating_add(destination.stderr.len()),
    );
    let stdout_remaining = total_remaining;
    let stdout_count = source.stdout.len().min(stdout_remaining);
    let stderr_remaining = total_remaining.saturating_sub(stdout_count);
    let stderr_count = source.stderr.len().min(stderr_remaining);
    destination
        .stdout
        .extend_from_slice(&source.stdout[..stdout_count]);
    destination
        .stderr
        .extend_from_slice(&source.stderr[..stderr_count]);
    destination.stdout_closed |= source.stdout_closed;
    destination.stderr_closed |= source.stderr_closed;
    destination.output_incomplete |= source.output_incomplete
        || stdout_count < source.stdout.len()
        || stderr_count < source.stderr.len();
    destination.cancellation_observed |= source.cancellation_observed;
}

fn poll_child_until_exit(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
    capture_limit: usize,
) -> Result<(ChildExit, ChildOutput), CommandFailure> {
    #[cfg(not(windows))]
    let _ = capture_limit;
    #[cfg(windows)]
    let mut polled_output = ChildOutput::default();
    loop {
        if let Some(reason) = cancellation.reason() {
            let cleanup = child.cancel(130).err().map(|error| error.to_string());
            return Err(CommandFailure::cancelled_with_cleanup(reason, cleanup));
        }

        #[cfg(windows)]
        {
            let chunk = child.read_output().map_err(|error| {
                let cleanup = child.cancel(130).err().map(|failure| failure.to_string());
                CommandFailure::ordinary_with_cleanup(error.to_string(), cleanup)
            })?;
            merge_captured_output(&mut polled_output, chunk, capture_limit);
        }

        match child.try_wait().map_err(|error| {
            let cleanup = child.cancel(130).err().map(|failure| failure.to_string());
            CommandFailure::ordinary_with_cleanup(error.to_string(), cleanup)
        })? {
            Some(exit) => {
                #[cfg(windows)]
                {
                    return Ok((exit, polled_output));
                }

                #[cfg(not(windows))]
                {
                    return Ok((exit, ChildOutput::default()));
                }
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn drain_child_output(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
) -> Result<ChildOutput, CommandFailure> {
    child
        .drain_output_with(|| cancellation.reason().is_some())
        .map_err(|error| {
            let cleanup = child.cancel(130).err().map(|failure| failure.to_string());
            CommandFailure::ordinary_with_cleanup(error.to_string(), cleanup)
        })
}

#[cfg(windows)]
fn finalize_child_output(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
    mut polled_output: ChildOutput,
    capture_limit: usize,
) -> Result<(ChildExit, ChildOutput), CommandFailure> {
    let final_output = drain_child_output(child, cancellation)?;
    merge_captured_output(&mut polled_output, final_output, capture_limit);

    complete_child_output(child, cancellation, polled_output, capture_limit)
}

#[cfg(not(windows))]
fn finalize_child_output(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
    _polled_output: ChildOutput,
    capture_limit: usize,
) -> Result<(ChildExit, ChildOutput), CommandFailure> {
    let final_output = drain_child_output(child, cancellation)?;
    complete_child_output(child, cancellation, final_output, capture_limit)
}

fn complete_child_output(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
    mut output: ChildOutput,
    capture_limit: usize,
) -> Result<(ChildExit, ChildOutput), CommandFailure> {
    if output.output_incomplete && !streams_closed(&output) {
        let cleanup = child.cancel(130).err().map(|failure| failure.to_string());
        return Err(CommandFailure::ordinary_with_cleanup(
            "update command did not settle its output streams before the retention deadline",
            cleanup,
        ));
    }
    if let Some(reason) = cancellation.reason() {
        let cleanup = child.cancel(130).err().map(|error| error.to_string());
        return Err(CommandFailure::cancelled_with_cleanup(reason, cleanup));
    }

    let exit = child.wait().map_err(|error| {
        let cleanup = child.cancel(130).err().map(|failure| failure.to_string());
        CommandFailure::ordinary_with_cleanup(error.to_string(), cleanup)
    })?;
    normalize_captured_output(&mut output, capture_limit);
    Ok((exit, output))
}

fn normalize_captured_output(output: &mut ChildOutput, limit: usize) {
    let total = output.stdout.len().saturating_add(output.stderr.len());
    if total <= limit {
        return;
    }
    let stdout_len = output.stdout.len().min(limit);
    output.stdout.truncate(stdout_len);
    output.stderr.truncate(limit.saturating_sub(stdout_len));
    output.output_incomplete = true;
}

fn streams_closed(output: &ChildOutput) -> bool {
    output.stdout_closed && output.stderr_closed
}

struct FsHost;
impl crate::update_runtime::BunInstallationHost for FsHost {
    fn canonical_path(&self, path: &Path) -> Result<PathBuf, String> {
        std::fs::canonicalize(path).map_err(|error| error.to_string())
    }
    fn is_file(&self, path: &Path) -> Result<bool, String> {
        Ok(std::fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false))
    }
}

struct NpmHost<'a> {
    environment: &'a BTreeMap<String, String>,
    cancellation: &'a Cancellation,
}
impl crate::update_runtime::NpmInstallationHost for NpmHost<'_> {
    fn canonical_path(&self, path: &Path) -> Result<PathBuf, String> {
        std::fs::canonicalize(path).map_err(|error| error.to_string())
    }
    fn global_root(&self) -> Result<PathBuf, String> {
        command_path(
            &["npm", "root", "--global"],
            self.environment,
            self.cancellation,
        )
        .map(PathBuf::from)
    }
    fn global_prefix(&self) -> Result<PathBuf, String> {
        command_path(
            &["npm", "prefix", "--global"],
            self.environment,
            self.cancellation,
        )
        .map(PathBuf::from)
    }
}

fn command_path(
    command: &[&str],
    environment: &BTreeMap<String, String>,
    cancellation: &Cancellation,
) -> Result<String, String> {
    if let Some(reason) = cancellation.reason() {
        return Err(format!("update command cancelled: {reason}"));
    }
    let spec = ChildLaunchSpec {
        executable: PathBuf::from(command[0]),
        arguments: ChildLaunchSpec::arguments(command[1..].iter().copied()),
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };
    let mut child = OwnedChildProcess::launch_with_environment(
        spec,
        &environment_pairs(environment),
        MAX_VERSION_OUTPUT_BYTES,
    )
    .map_err(|error| error.to_string())?;
    let completed = settle_command_child(&mut child, cancellation, MAX_VERSION_OUTPUT_BYTES)
        .map_err(|error| error.message)?;
    if completed.output.output_incomplete && !streams_closed(&completed.output) {
        return Err(
            "update command did not settle its output streams before the retention deadline".into(),
        );
    }
    if completed.output.output_incomplete {
        return Err("update command output exceeded the retention budget".into());
    }
    if completed.exit.code != 0 {
        return Err(String::from_utf8_lossy(&completed.output.stderr)
            .trim()
            .to_owned());
    }
    Ok(String::from_utf8_lossy(&completed.output.stdout)
        .trim()
        .to_owned())
}

fn environment_pairs(environment: &BTreeMap<String, String>) -> Vec<(OsString, OsString)> {
    environment
        .iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect()
}

fn installation_working_directory(installation: &UpdateInstallation) -> Option<PathBuf> {
    match installation {
        UpdateInstallation::Bun {
            global_directory, ..
        } => Some(global_directory.clone()),
        UpdateInstallation::Npm { .. } => None,
    }
}
fn installation_working_directory_opt(
    installation: Option<&UpdateInstallation>,
) -> Option<PathBuf> {
    installation.map(installation_working_directory).flatten()
}

#[derive(Debug)]
struct UpdateError {
    kind: &'static str,
    latest_version: Option<String>,
    remediation: String,
}
impl UpdateError {
    fn from_command(error: CommandFailure, latest: Option<String>, fallback: &'static str) -> Self {
        Self {
            kind: if error.cancelled {
                "cancelled"
            } else {
                fallback
            },
            latest_version: latest,
            remediation: error.message,
        }
    }
    fn version_check(message: impl Into<String>) -> Self {
        Self {
            kind: "version-check",
            latest_version: None,
            remediation: message.into(),
        }
    }
    fn verification(message: impl Into<String>, latest: Option<String>) -> Self {
        Self {
            kind: "verification",
            latest_version: latest,
            remediation: message.into(),
        }
    }
    fn unknown_installation(message: impl Into<String>, latest: Option<String>) -> Self {
        Self {
            kind: "unknown-install-method",
            latest_version: latest,
            remediation: message.into(),
        }
    }
    fn cancelled(message: String) -> Self {
        Self {
            kind: "cancelled",
            latest_version: None,
            remediation: message,
        }
    }
}

#[derive(Debug)]
struct CommandFailure {
    message: String,
    cancelled: bool,
}
impl CommandFailure {
    fn ordinary(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cancelled: false,
        }
    }
    fn cancelled(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cancelled: true,
        }
    }

    fn ordinary_with_cleanup(message: impl Into<String>, cleanup: Option<String>) -> Self {
        Self::ordinary(format!(
            "{}{}",
            message.into(),
            cleanup
                .map(|failure| format!("; cleanup failed: {failure}"))
                .unwrap_or_default()
        ))
    }
    fn cancelled_with_cleanup(reason: &str, cleanup: Option<String>) -> Self {
        Self::cancelled(format!(
            "update command cancelled: {reason}{}",
            cleanup
                .map(|failure| format!("; cleanup failed: {failure}"))
                .unwrap_or_default()
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<String>,
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => compare_prerelease(&self.pre, &other.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(left: &[String], right: &[String]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for (a, b) in left.iter().zip(right) {
        let a_numeric = a.chars().all(|character| character.is_ascii_digit());
        let b_numeric = b.chars().all(|character| character.is_ascii_digit());
        let ordering = match (a_numeric, b_numeric) {
            (true, true) => a
                .trim_start_matches('0')
                .len()
                .cmp(&b.trim_start_matches('0').len())
                .then_with(|| a.trim_start_matches('0').cmp(b.trim_start_matches('0'))),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => a.cmp(b),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}
impl Version {
    fn parse(value: &str) -> Option<Self> {
        let value = value.strip_prefix('v').unwrap_or(value);
        let (without_build, _) = value.split_once('+').map_or((value, ""), |parts| parts);
        let (core, pre) = without_build
            .split_once('-')
            .map_or((without_build, ""), |parts| parts);
        let mut numbers = core.split('.');
        let parse_core = |part: &str| {
            (!part.is_empty() && (part == "0" || !part.starts_with('0')))
                .then(|| part.parse::<u64>().ok())
                .flatten()
        };
        let version = Self {
            major: parse_core(numbers.next()?)?,
            minor: parse_core(numbers.next()?)?,
            patch: parse_core(numbers.next()?)?,
            pre: if pre.is_empty() {
                Vec::new()
            } else {
                pre.split('.').map(str::to_owned).collect()
            },
        };
        (numbers.next().is_none()
            && version.pre.iter().all(|part| {
                !part.is_empty()
                    && (!part.chars().all(|character| character.is_ascii_digit())
                        || (part == "0" || !part.starts_with('0')))
            }))
        .then_some(version)
    }
}
impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(formatter, "-{}", self.pre.join("."))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn executable_fixture(directory: &Path, name: &str, source: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, source).expect("fixture script should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path)
                .expect("fixture metadata should be readable")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("fixture script should be executable");
        }
        path
    }

    fn npm_fixture_environment(bin: &Path) -> BTreeMap<String, String> {
        let mut environment = BTreeMap::new();
        environment.insert("PATH".into(), bin.to_string_lossy().into_owned());
        environment.insert("HOME".into(), "/tmp/rea-test-home".into());
        environment
    }

    fn package_fixture(root: &Path) -> PathBuf {
        let package_root = root.join("lib/node_modules").join(PACKAGE_NAME);
        fs::create_dir_all(package_root.join("scripts"))
            .expect("package fixture directories should be created");
        fs::write(package_root.join("scripts/rea.mjs"), "fixture")
            .expect("package launcher fixture should be written");
        package_root
    }

    fn npm_script(latest: &str, prefix: &Path, marker: &Path) -> String {
        format!(
            "#!/bin/sh\ncase \"$*\" in\n  *'root --global'*) printf '%s\\n' '{prefix}/lib/node_modules';;\n  *'prefix --global'*) printf '%s\\n' '{prefix}';;\n  *'view --global'*) printf '\"{latest}\"\\n';;\n  *'install --global'*) printf 'installed\\n' >> '{marker}';;\nesac\n",
            prefix = prefix.display(),
            latest = latest,
            marker = marker.display(),
        )
    }

    #[test]
    fn version_ordering_follows_semver_prerelease_rules() {
        assert!(Version::parse("1.0.0-alpha").unwrap() < Version::parse("1.0.0").unwrap());
        assert!(
            Version::parse("1.0.0-alpha.2").unwrap() < Version::parse("1.0.0-alpha.10").unwrap()
        );
        assert!(Version::parse("1.0.0+build.7").unwrap() == Version::parse("1.0.0").unwrap());
        assert!(Version::parse("01.0.0").is_none());
    }

    #[test]
    fn update_check_reports_available_without_running_install() {
        let temp = TempDir::new().expect("temporary update fixture should exist");
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).expect("fixture bin should be created");
        let prefix = temp.path().join("prefix");
        let package_root = package_fixture(&prefix);
        let marker = temp.path().join("install-marker");
        executable_fixture(&bin, "npm", &npm_script("2.0.0", &prefix, &marker));
        let environment = npm_fixture_environment(&bin);

        let result = run_update_check(
            "1.0.0",
            &package_root,
            &environment,
            &Cancellation::default(),
        );

        assert_eq!(result["status"], "available");
        assert_eq!(result["latestVersion"], "2.0.0");
        assert!(!marker.exists(), "update-check must never run installation");
    }

    #[test]
    fn update_invokes_maintenance_only_after_verified_installation() {
        let temp = TempDir::new().expect("temporary update fixture should exist");
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).expect("fixture bin should be created");
        let prefix = temp.path().join("prefix");
        let package_root = package_fixture(&prefix);
        let marker = temp.path().join("install-marker");
        executable_fixture(&bin, "npm", &npm_script("2.0.0", &prefix, &marker));
        executable_fixture(&bin, "node", "#!/bin/sh\n/bin/sleep 1\nprintf '2.0.0\\n'\n");
        let mut environment = npm_fixture_environment(&bin);
        environment.insert(
            "REA_NODE".into(),
            bin.join("node").to_string_lossy().into_owned(),
        );
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);

        let result = run_update_with_maintenance(
            "1.0.0",
            &package_root,
            &environment,
            &Cancellation::default(),
            move |installation| {
                callback_called.store(true, Ordering::Release);
                json!({"status": "planned", "manager": installation.manager_name()})
            },
        );

        assert_eq!(result["status"], "updated", "{result}");
        assert_eq!(result["maintenance"]["status"], "planned");
        assert_eq!(result["maintenance"]["manager"], "npm");
        assert!(called.load(Ordering::Acquire));
        assert!(
            marker.exists(),
            "verified update should run the package install"
        );
    }

    #[test]
    fn cancelled_command_preserves_cancellation_reason_and_attempts_cleanup() {
        let temp = TempDir::new().expect("temporary update fixture should exist");
        let command = executable_fixture(temp.path(), "slow-command", "#!/bin/sh\nsleep 5\n");
        let cancellation = Cancellation::default();
        let trigger = cancellation.clone();
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            trigger.cancel("test cancellation");
        });
        let environment = BTreeMap::new();
        let workflow = UpdateWorkflow::new("1.0.0", temp.path(), &environment, &cancellation, true);

        let result =
            workflow.run_command(&[command.to_string_lossy().into_owned()], None, 1024, true);
        thread.join().expect("cancellation trigger should settle");
        let failure = result.expect_err("cancelled command should fail");
        assert!(failure.cancelled);
        assert!(failure.message.contains("test cancellation"));
    }

    #[test]
    fn failed_command_reports_bounded_diagnostic_truncation() {
        let temp = TempDir::new().expect("temporary update fixture should exist");
        let command = executable_fixture(
            temp.path(),
            "noisy-command",
            "#!/bin/sh\nprintf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n' >&2\nexit 9\n",
        );
        let environment = BTreeMap::new();
        let cancellation = Cancellation::default();
        let workflow = UpdateWorkflow::new("1.0.0", temp.path(), &environment, &cancellation, true);
        let result =
            workflow.run_command(&[command.to_string_lossy().into_owned()], None, 16, false);
        let failure = result.expect_err("failed command should return diagnostics");
        assert!(
            failure
                .message
                .contains("Update diagnostics truncated at 16 bytes")
        );
    }
}
