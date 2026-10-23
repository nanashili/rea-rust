//! Live, read-only ADB package acquisition.
//!
//! The caller selects the ADB binary, device, package, and output directory.
//! This adapter owns each short-lived child and removes only the package
//! directory it created when acquisition cannot be completed.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use rea_application::adb;
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::{
    process::launcher::{ChildLaunchSpec, OwnedChildProcess},
    process::windows::job::WindowsJobLimits,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const OPERATION: &str = adb::package_pull::OPERATION;

pub fn supports(operation: &str) -> bool {
    operation == OPERATION
}

pub fn dispatch(
    operation: &str,
    input: &Value,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    if !supports(operation) {
        return Err(invalid("unsupported live ADB package operation"));
    }
    pull(input, cancellation)
}

pub fn pull(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    let request = Request::parse(input)?;
    ensure_active(cancellation)?;

    let paths = run_adb(
        &request.binary_path,
        ChildLaunchSpec::arguments([
            "-s",
            request.serial.as_str(),
            "shell",
            "pm",
            "path",
            request.package.as_str(),
        ]),
        cancellation,
    )?;
    if paths.code != 0 {
        return Err(provider_failure("adb pm path failed"));
    }
    let device_paths = parse_paths(&paths.stdout)?;
    if device_paths.is_empty() {
        return Err(provider_failure("adb pm path returned no APK paths"));
    }

    let package_directory = request.output_directory.join(&request.package);
    if package_directory.exists() {
        return Err(invalid("package output directory already exists"));
    }
    fs::create_dir_all(&package_directory).map_err(|error| output_failure(error.to_string()))?;

    let result = pull_artifacts(&request, &package_directory, &device_paths, cancellation);
    match result {
        Ok(artifacts) => Ok(json!({"result": {
            "client": {"binary_path": request.binary_path, "path_source": "path", "version": null, "installed_path": null},
            "serial": request.serial, "package_name": request.package,
            "output_directory": request.output_directory,
            "artifacts": artifacts, "failures": [], "coverage": "complete"
        }})),
        Err(failure) => {
            let _ = fs::remove_dir_all(&package_directory);
            Err(failure)
        }
    }
}

fn pull_artifacts(
    request: &Request,
    package_directory: &Path,
    paths: &[String],
    cancellation: &Cancellation,
) -> Result<Vec<Value>, Failure> {
    let mut artifacts = Vec::with_capacity(paths.len());
    for device_path in paths {
        ensure_active(cancellation)?;
        let file_name = Path::new(device_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("pm path contains an invalid APK path"))?;
        let local_path = package_directory.join(file_name);
        let output = run_adb(
            &request.binary_path,
            vec![
                OsString::from("-s"),
                OsString::from(&request.serial),
                OsString::from("pull"),
                OsString::from(device_path),
                local_path.clone().into_os_string(),
            ],
            cancellation,
        )?;
        if output.code != 0 {
            return Err(provider_failure("adb pull failed"));
        }
        let bytes = fs::read(&local_path).map_err(|error| output_failure(error.to_string()))?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let role = if file_name == "base.apk" {
            "base"
        } else if file_name.starts_with("split_") {
            "split"
        } else {
            "unknown"
        };
        artifacts.push(json!({"device_path": device_path, "file_name": file_name, "local_path": local_path, "bytes": bytes.len(), "sha256": digest, "role": role, "role_basis": "file_name"}));
    }
    Ok(artifacts)
}

fn parse_paths(stdout: &[u8]) -> Result<Vec<String>, Failure> {
    let text = String::from_utf8_lossy(stdout);
    let mut paths = Vec::new();
    for line in text.lines() {
        let path = line
            .strip_prefix("package:")
            .ok_or_else(|| invalid("pm path reported an unrecognized line"))?;
        if path.is_empty() || !path.starts_with('/') || path.contains('\0') {
            return Err(invalid("pm path reported an unsafe device path"));
        }
        paths.push(path.to_owned());
    }
    Ok(paths)
}

struct CommandOutput {
    code: u32,
    stdout: Vec<u8>,
}

fn run_adb(
    binary_path: &str,
    arguments: Vec<OsString>,
    cancellation: &Cancellation,
) -> Result<CommandOutput, Failure> {
    let mut child = OwnedChildProcess::launch(ChildLaunchSpec {
        executable: PathBuf::from(binary_path),
        arguments,
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    })
    .map_err(|error| launch_failure(error.message))?;
    loop {
        if cancellation.reason().is_some() {
            child
                .cancel(130)
                .map_err(|error| launch_failure(error.message))?;
            return Err(cancelled(cancellation));
        }
        if let Some(exit) = child
            .try_wait()
            .map_err(|error| launch_failure(error.message))?
        {
            let output = child
                .drain_output()
                .map_err(|error| launch_failure(error.message))?;
            return Ok(CommandOutput {
                code: exit.code,
                stdout: output.stdout,
            });
        }
        thread::sleep(Duration::from_millis(5));
    }
}

struct Request {
    binary_path: String,
    serial: String,
    package: String,
    output_directory: PathBuf,
}
impl Request {
    fn parse(input: &Value) -> Result<Self, Failure> {
        let object = input
            .as_object()
            .ok_or_else(|| invalid("ADB package input must be an object"))?;
        let text = |field: &str| {
            object
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid(&format!("{field} is required")))
        };
        let binary_path = object
            .get("binary_path")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("adb")
            .to_owned();
        let serial = text("serial")?;
        let package = text("package")?;
        let output_directory = PathBuf::from(text("output_directory")?);
        if serial
            .chars()
            .any(|character| character.is_whitespace() || character == '\0')
            || package
                .chars()
                .any(|character| character.is_whitespace() || character == '\0')
        {
            return Err(invalid(
                "serial and package must not contain whitespace or NUL",
            ));
        }
        Ok(Self {
            binary_path,
            serial,
            package,
            output_directory,
        })
    }
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    cancellation
        .reason()
        .map_or(Ok(()), |reason| Err(cancelled_reason(reason)))
}
fn cancelled(cancellation: &Cancellation) -> Failure {
    cancelled_reason(cancellation.reason().unwrap_or("request cancelled"))
}
fn cancelled_reason(reason: &str) -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        reason.into(),
        true,
        "Retry the ADB package pull.".into(),
        details(),
    )
}
fn launch_failure(reason: String) -> Failure {
    Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        reason,
        false,
        "Select an executable ADB client and online device.".into(),
        details(),
    )
}
fn provider_failure(reason: &str) -> Failure {
    Failure::new(
        "provider_failure",
        "provider_execution",
        reason.into(),
        false,
        "Select an online device and retry.".into(),
        details(),
    )
}
fn output_failure(reason: String) -> Failure {
    Failure::new(
        "output_failure",
        "output_failure",
        reason,
        false,
        "Select a writable output directory and retry.".into(),
        details(),
    )
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a caller-selected ADB package pull.".into(),
        details(),
    )
}
fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", Detail::Text(OPERATION.into()))])
}
