//! Live, read-only probe of the caller-selected Apktool launcher.
//!
//! Launcher selection and the short-lived `--version` child belong to this
//! runtime boundary. The application module only interprets the bounded output,
//! so a captured observation never gains process-execution authority.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use rea_application::apktool::client::{
    self as apktool_client, COMMAND_ENV, CapturedVersionOutput, ClientInspection, CommandSelection,
    CommandSource,
};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::{
    process::launcher::{ChildLaunchSpec, OwnedChildProcess},
    process::windows::job::WindowsJobLimits,
};

/// Public operation handled by this live adapter.
pub const OPERATION: &str = apktool_client::OPERATION;

const VERSION_TIMEOUT: Duration = Duration::from_secs(20);
const VERSION_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Host facts that select the launcher. Kept explicit so tests and adapters
/// never read ambient process state implicitly.
#[derive(Clone, Debug, Default)]
pub struct LauncherEnvironment {
    pub configured_command: Option<OsString>,
    pub path: Option<OsString>,
    pub path_ext: Option<OsString>,
    pub current_directory: Option<PathBuf>,
    pub search_current_directory: bool,
}

impl LauncherEnvironment {
    /// Snapshot the current process environment once at the adapter boundary.
    pub fn current() -> Self {
        Self {
            configured_command: std::env::var_os(COMMAND_ENV),
            path: std::env::var_os("PATH"),
            path_ext: std::env::var_os("PATHEXT"),
            current_directory: std::env::current_dir().ok(),
            search_current_directory: std::env::var_os("NoDefaultCurrentDirectoryInExePath")
                .is_none(),
        }
    }
}

/// Resolve, probe and interpret the selected launcher.
pub fn inspect(
    environment: &LauncherEnvironment,
    cancellation: &Cancellation,
) -> Result<ClientInspection, Failure> {
    ensure_active(cancellation)?;
    let selection = resolve(environment)?;
    let executable = launch_path(&selection, environment)?;
    let output = run_version(&selection, &executable, cancellation)?;
    apktool_client::inspect(selection, output)
}

/// Preserve an explicit launcher or select `apktool` from PATH.
fn resolve(environment: &LauncherEnvironment) -> Result<CommandSelection, Failure> {
    if let Some(configured) = environment
        .configured_command
        .as_ref()
        .filter(|value| !value.to_string_lossy().trim().is_empty())
    {
        let configured_text = configured.to_string_lossy().into_owned();
        if !Path::new(configured).is_absolute() {
            return Err(configuration_failure(
                "not_configured",
                format!("{COMMAND_ENV} must be an absolute path to the apktool launcher"),
                BTreeMap::from([("configured_command", Detail::Text(configured_text))]),
            ));
        }
        return Ok(CommandSelection {
            command: configured_text,
            command_source: CommandSource::Environment,
        });
    }
    Ok(CommandSelection {
        command: "apktool".into(),
        command_source: CommandSource::Path,
    })
}

/// The owned launcher requires a concrete executable. POSIX retains execvp
/// semantics through a PATH search; Windows applies PATHEXT like the original.
fn launch_path(
    selection: &CommandSelection,
    environment: &LauncherEnvironment,
) -> Result<PathBuf, Failure> {
    if selection.command_source == CommandSource::Environment {
        return Ok(PathBuf::from(&selection.command));
    }
    let directories = environment
        .path
        .as_ref()
        .map(|path| std::env::split_paths(path).collect::<Vec<_>>())
        .unwrap_or_default();
    let candidates: Vec<PathBuf> = if cfg!(windows) {
        let extensions = environment
            .path_ext
            .as_ref()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".EXE;.COM;.BAT;.CMD".into());
        let extensions = extensions
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if let Some(invalid) = extensions.iter().find(|extension| {
            !extension.starts_with('.') || extension.contains(['\\', '/', ':', '\0'])
        }) {
            return Err(configuration_failure(
                "not_configured",
                "Windows PATHEXT must contain filename extensions, not paths".into(),
                BTreeMap::from([
                    ("selected_command", Detail::Text("apktool".into())),
                    ("command_source", Detail::Text("path".into())),
                    ("invalid_extension", Detail::Text(invalid.clone())),
                ]),
            ));
        }
        let mut search = Vec::new();
        if environment.search_current_directory
            && let Some(current) = &environment.current_directory
        {
            search.push(current.clone());
        }
        search.extend(directories);
        search
            .iter()
            .flat_map(|directory| {
                extensions
                    .iter()
                    .map(move |extension| directory.join(format!("apktool{extension}")))
            })
            .collect()
    } else {
        directories
            .iter()
            .map(|directory| directory.join("apktool"))
            .collect()
    };
    candidates
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
        .ok_or_else(|| missing_launcher(selection))
}

#[cfg(unix)]
fn is_executable_file(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(candidate)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(candidate: &Path) -> bool {
    std::fs::metadata(candidate).is_ok_and(|metadata| metadata.is_file())
}

fn run_version(
    selection: &CommandSelection,
    executable: &Path,
    cancellation: &Cancellation,
) -> Result<CapturedVersionOutput, Failure> {
    if cfg!(windows) && is_windows_batch_file(executable) {
        return Err(configuration_failure(
            "not_configured",
            "The selected apktool launcher is a batch file, which the native owned launcher cannot run without cmd.exe".into(),
            BTreeMap::from([
                ("selected_command", Detail::Text(selection.command.clone())),
                ("command_source", Detail::Text(source_name(selection).into())),
            ]),
        ));
    }
    let mut child = match OwnedChildProcess::launch(ChildLaunchSpec {
        executable: executable.to_path_buf(),
        arguments: ChildLaunchSpec::arguments(["--version"]),
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    }) {
        Ok(child) => child,
        Err(error) if error.operation == "create_process" => {
            return Err(missing_launcher(selection));
        }
        Err(error) => return Err(execution_failure(selection, error.to_string())),
    };
    let started = Instant::now();
    let exit = loop {
        if cancellation.reason().is_some() {
            let cleanup = child.cancel(130).err();
            let mut failure = cancelled(cancellation);
            if let Some(cleanup) = cleanup {
                failure.detail("cleanup_failure", Detail::Text(cleanup.to_string()));
            }
            return Err(failure);
        }
        if started.elapsed() >= VERSION_TIMEOUT {
            let cleanup = child.cancel(1).err();
            let mut failure = Failure::new(
                "timeout",
                "timeout",
                format!(
                    "inspect_apktool_client timed out after {} ms",
                    VERSION_TIMEOUT.as_millis()
                ),
                true,
                "Retry with a responsive apktool launcher.".into(),
                selection_details(selection),
            );
            if let Some(cleanup) = cleanup {
                failure.detail("cleanup_failure", Detail::Text(cleanup.to_string()));
            }
            return Err(failure);
        }
        match child.try_wait() {
            Ok(Some(exit)) => break exit,
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => return Err(execution_failure(selection, error.to_string())),
        }
    };
    let output = child
        .drain_output()
        .map_err(|error| execution_failure(selection, error.to_string()))?;
    if output.output_incomplete || output.exceeds_limit(VERSION_MAX_OUTPUT_BYTES) {
        let mut details = selection_details(selection);
        details.insert(
            "max_output_bytes",
            Detail::Count(VERSION_MAX_OUTPUT_BYTES as u64),
        );
        return Err(Failure::new(
            "version_unresolved",
            "version_unresolved",
            "The selected apktool launcher did not report a usable version".into(),
            false,
            "Use an Apktool launcher whose --version output is bounded.".into(),
            details,
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if exit.code != 0 {
        let mut details = selection_details(selection);
        details.insert("exit_code", Detail::Count(u64::from(exit.code)));
        details.insert(
            "stderr_excerpt",
            Detail::Text(stderr.chars().take(512).collect()),
        );
        return Err(Failure::new(
            "version_unresolved",
            "version_unresolved",
            "The selected apktool launcher did not report a usable version".into(),
            false,
            "Use an Apktool launcher that reports a semantic version from --version.".into(),
            details,
        ));
    }
    Ok(CapturedVersionOutput { stdout, stderr })
}

fn is_windows_batch_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
        })
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    match cancellation.reason() {
        Some(_) => Err(cancelled(cancellation)),
        None => Ok(()),
    }
}

fn cancelled(cancellation: &Cancellation) -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        format!(
            "inspect_apktool_client was cancelled: {}",
            cancellation.reason().unwrap_or("request cancelled")
        ),
        true,
        "Retry the Apktool client inspection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn missing_launcher(selection: &CommandSelection) -> Failure {
    let mut details = selection_details(selection);
    details.insert(
        "remediation",
        Detail::Text(format!(
            "Set {COMMAND_ENV} to an absolute apktool launcher (the upstream wrapper or a java -jar script)"
        )),
    );
    Failure::new(
        "executable_missing",
        "provider_unavailable",
        format!(
            "The selected apktool launcher was not found: {}",
            selection.command
        ),
        false,
        format!("Set {COMMAND_ENV} to an absolute Apktool launcher or put apktool on PATH."),
        details,
    )
}

fn execution_failure(selection: &CommandSelection, reason: String) -> Failure {
    let mut details = selection_details(selection);
    details.insert("reason", Detail::Text(reason));
    Failure::new(
        "provider_failure",
        "provider_execution",
        "The selected apktool launcher could not be supervised".into(),
        true,
        "Retry after confirming the selected launcher is executable.".into(),
        details,
    )
}

fn configuration_failure(
    code: &'static str,
    message: String,
    extra: BTreeMap<&'static str, Detail>,
) -> Failure {
    let mut details = BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]);
    details.extend(extra);
    Failure::new(
        code,
        "provider_unavailable",
        message,
        false,
        format!("Set {COMMAND_ENV} to an absolute Apktool launcher or put apktool on PATH."),
        details,
    )
}

fn selection_details(selection: &CommandSelection) -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("selected_command", Detail::Text(selection.command.clone())),
        (
            "command_source",
            Detail::Text(source_name(selection).into()),
        ),
    ])
}

fn source_name(selection: &CommandSelection) -> &'static str {
    match selection.command_source {
        CommandSource::Environment => "environment",
        CommandSource::Path => "path",
    }
}
