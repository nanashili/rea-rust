//! Mutating ADB operations: push, install, uninstall and activity control.
//!
//! Compatibility owner: the `pushFile`, `installPackage`, `uninstallPackage`,
//! `startApp`, `startActivity`, `runAmStart` and `stopApp` methods of
//! `AdbProvider`. The authority gates (overwrite refusal, digest verification,
//! device verdicts) are ported exactly; no gate is added or relaxed.
use crate::adb::command::{
    AdbCommandTarget, adb_arguments, package_change_refusal, probe_adb_path_existence, run_adb,
};
use crate::adb::files::{resolve_path, snapshot_adb_input};
use crate::adb::provider::{
    Context, PACKAGE_LIST_TIMEOUT_MS, PM_PATH_MAX_OUTPUT_BYTES, PULL_MAX_OUTPUT_BYTES,
    PULL_TIMEOUT_MS, SETTINGS_TIMEOUT_MS, SHELL_TIMEOUT_MS, finish, parameters, serial_of,
};
use crate::adb::shell_output::{
    parse_am_start_output, parse_package_change_output, parse_resolve_activity_output,
};
use crate::common::workspace::PrivateRoot;
use rea_core::analysis_error::{AnalysisError, CapturedOutput, InputIssue};
use rea_core::evidence::envelope::Evidence;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::OnceLock;

fn require_local_file(operation: &str, path: &Path) -> Result<(), AnalysisError> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        _ => Err(AnalysisError::input(
            operation,
            vec![InputIssue::new(
                &[],
                "custom",
                format!("The local file does not exist: {}", path.display()),
            )],
        )),
    }
}

/// Create a private runtime root in the host temporary directory.
fn runtime_root(
    ctx: &Context<'_>,
    environment: &std::collections::HashMap<String, String>,
    prefix: &str,
) -> Result<PrivateRoot, AnalysisError> {
    let parent = crate::common::env::temporary_directory(environment);
    PrivateRoot::create(&parent, prefix).map_err(|error| {
        AnalysisError::output(ctx.operation, "Could not create an ADB private workspace")
            .with_diagnostics(crate::common::errors::object(
                json!({ "io_error": error.to_string() }),
            ))
    })
}

/// Entry used by the dispatcher with access to the session environment.
pub(crate) fn push_file_env(
    ctx: &Context<'_>,
    input: &Value,
    environment: &std::collections::HashMap<String, String>,
) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let local_path = resolve_path(
        input
            .get("local_path")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let device_path = input
        .get("device_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let overwrite = input
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    require_local_file(ctx.operation, &local_path)?;

    let mut root = runtime_root(ctx, environment, "rea-adb-input-")?;
    let outcome = push_within_root(
        ctx,
        serial,
        &local_path,
        device_path,
        overwrite,
        root.path(),
    );
    let _ = root.close();
    outcome
}

fn push_within_root(
    ctx: &Context<'_>,
    serial: &str,
    local_path: &Path,
    device_path: &str,
    overwrite: bool,
    root_path: &Path,
) -> Result<Evidence, AnalysisError> {
    let digest = snapshot_adb_input(local_path, root_path, ctx.operation, ctx.cancellation)?;
    let exists = probe_adb_path_existence(
        ctx.operation,
        serial,
        device_path,
        &ctx.selection.binary,
        Context::limits(SETTINGS_TIMEOUT_MS, 1024),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    if exists && !overwrite {
        return Err(AnalysisError::output(
            ctx.operation,
            format!(
                "The device path already exists and overwrite was not requested: {device_path}"
            ),
        ));
    }
    let push_args = adb_arguments(Some(serial), &["push", &digest.path, device_path]);
    run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: Some(device_path.to_owned()),
            local_path: Some(digest.path.clone()),
        },
        &ctx.selection.binary,
        &push_args,
        Context::limits(PULL_TIMEOUT_MS, PULL_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;

    let local_path_str = local_path.to_string_lossy().into_owned();
    let receipt = |device_sha256: Option<&str>, source: &str, extra: Vec<String>| -> Value {
        let mut limitations =
            vec!["Push writes a private snapshot of the caller's file to the device".to_owned()];
        limitations.extend(extra);
        json!({
            "result": {
                "client": ctx.client,
                "serial": serial,
                "local_path": local_path_str,
                "device_path": device_path,
                "bytes": digest.bytes,
                "sha256": digest.sha256,
                "device_sha256": device_sha256,
                "overwritten": exists,
                "device_digest_source": source,
            },
            "limitations": limitations,
        })
    };

    let device_digest_args = adb_arguments(Some(serial), &["shell", "sha256sum", device_path]);
    let device_digest = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: Some(device_path.to_owned()),
            local_path: None,
        },
        &ctx.selection.binary,
        &device_digest_args,
        Context::limits(SHELL_TIMEOUT_MS, 1024),
        ctx.cancellation,
    );
    match device_digest {
        Err(command_error) => {
            let error = ctx.retain_child(command_error);
            let cancelled = matches!(
                error.kind,
                rea_core::analysis_error::ErrorKind::Cancelled { .. }
            );
            let extra = vec![if cancelled {
                "The device-side digest check was cancelled after push completed".to_owned()
            } else {
                "The device did not answer sha256sum, so the transfer is not device-side verified"
                    .to_owned()
            }];
            let receipt_value = receipt(None, "unavailable", extra);
            if cancelled {
                let (result, limitations) = split_receipt(receipt_value);
                let evidence = finish(
                    ctx,
                    push_parameters(serial, local_path, device_path, overwrite),
                    result.clone(),
                    limitations,
                    None,
                )?;
                // A cancelled device digest keeps the complete receipt as the
                // partial observation.
                return Err(AnalysisError::cancelled(ctx.operation)
                    .retain_partial_observation(evidence.into_value()));
            }
            let (result, limitations) = split_receipt(receipt_value);
            finish(
                ctx,
                push_parameters(serial, local_path, device_path, overwrite),
                result,
                limitations,
                None,
            )
        }
        Ok(ran) => {
            let device_sha = device_digest_regex()
                .captures(&ran.stdout)
                .map(|caps| caps[1].to_owned());
            let receipt_value = receipt(device_sha.as_deref(), "device_sha256sum", Vec::new());
            let (result, limitations) = split_receipt(receipt_value);
            if let Some(device_sha) = device_sha.as_deref()
                && device_sha != digest.sha256
            {
                let evidence = finish(
                    ctx,
                    push_parameters(serial, local_path, device_path, overwrite),
                    result.clone(),
                    limitations.clone(),
                    None,
                )?;
                return Err(AnalysisError::artifact_changed(
                    ctx.operation,
                    device_path,
                    format!(
                        "The device-reported digest does not match the staged local file: {}",
                        local_path.display()
                    ),
                )
                .retain_partial_observation(evidence.into_value()));
            }
            finish(
                ctx,
                push_parameters(serial, local_path, device_path, overwrite),
                result,
                limitations,
                None,
            )
        }
    }
}

fn device_digest_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^([a-f0-9]{64})\s").unwrap())
}

fn split_receipt(receipt: Value) -> (Value, Vec<String>) {
    let result = receipt.get("result").cloned().unwrap_or(Value::Null);
    let limitations = receipt
        .get("limitations")
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    (result, limitations)
}

/// Evidence parameters for push: the resolved local path and overwrite flag.
fn push_parameters(serial: &str, local_path: &Path, device_path: &str, overwrite: bool) -> Value {
    json!({
        "serial": serial,
        "local_path": local_path.to_string_lossy(),
        "device_path": device_path,
        "overwrite": overwrite,
    })
}

pub(crate) fn install_package_env(
    ctx: &Context<'_>,
    input: &Value,
    environment: &std::collections::HashMap<String, String>,
) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let apk_path = resolve_path(
        input
            .get("apk_path")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let replace = input
        .get("replace")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match std::fs::metadata(&apk_path) {
        Ok(metadata) if metadata.is_file() => {}
        _ => {
            return Err(AnalysisError::input(
                ctx.operation,
                vec![InputIssue::new(
                    &[],
                    "custom",
                    format!("The local APK does not exist: {}", apk_path.display()),
                )],
            ));
        }
    }
    let mut root = runtime_root(ctx, environment, "rea-adb-apk-")?;
    let outcome = install_within_root(ctx, serial, &apk_path, replace, root.path());
    let _ = root.close();
    outcome
}

fn install_within_root(
    ctx: &Context<'_>,
    serial: &str,
    apk_path: &Path,
    replace: bool,
    root_path: &Path,
) -> Result<Evidence, AnalysisError> {
    let digest = snapshot_adb_input(apk_path, root_path, ctx.operation, ctx.cancellation)?;
    let mut install_args: Vec<&str> = vec!["install"];
    if replace {
        install_args.push("-r");
    }
    install_args.push(&digest.path);
    let args = adb_arguments(Some(serial), &install_args);
    let installed = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: Some(apk_path.to_string_lossy().into_owned()),
            local_path: Some(digest.path.clone()),
        },
        &ctx.selection.binary,
        &args,
        Context::limits(PULL_TIMEOUT_MS, PULL_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    );
    let installed = match installed {
        Ok(result) => result,
        Err(command_error) => {
            if let Some(refusal) = package_change_refusal(ctx.operation, serial, &command_error) {
                return Err(refusal);
            }
            return Err(ctx.retain_child(command_error));
        }
    };
    let verdict = parse_package_change_output(&installed.stdout);
    if verdict.status == "failure" {
        return Err(AnalysisError::unsupported_target(
            ctx.operation,
            serial,
            verdict
                .reason
                .unwrap_or_else(|| "the device refused the installation".to_owned()),
        ));
    }
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "apk_path": apk_path.to_string_lossy(),
        "bytes": digest.bytes,
        "sha256": digest.sha256,
        "replace_requested": replace,
        "replaced": Value::Null,
    });
    finish(
        ctx,
        json!({ "serial": serial, "apk_path": apk_path.to_string_lossy(), "replace": replace }),
        result,
        vec![
            "Install changes device state; the installed APK's digest identifies the private host snapshot".to_owned(),
            "Whether an existing package was replaced is unknown; replace_requested records only the adb install mode".to_owned(),
        ],
        None,
    )
}

/// `uninstallPackage(...)`.
pub(crate) fn uninstall_package(
    ctx: &Context<'_>,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let package = input
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = adb_arguments(
        Some(serial),
        &["shell", "pm", "uninstall", "--user", "0", package],
    );
    let uninstalled = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(PACKAGE_LIST_TIMEOUT_MS, PULL_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    );
    let uninstalled = match uninstalled {
        Ok(result) => result,
        Err(command_error) => {
            if let Some(refusal) = package_change_refusal(ctx.operation, serial, &command_error) {
                return Err(refusal);
            }
            return Err(ctx.retain_child(command_error));
        }
    };
    let verdict = parse_package_change_output(&uninstalled.stdout);
    if verdict.status == "failure" {
        return Err(AnalysisError::unsupported_target(
            ctx.operation,
            serial,
            verdict
                .reason
                .unwrap_or_else(|| "the device refused the removal".to_owned()),
        ));
    }
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "package_name": package,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Uninstall explicitly requests user 0 without data retention (-k); device enforcement is not independently verified".to_owned(),
        ],
        None,
    )
}

/// `startApp(...)`.
pub(crate) fn start_app(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let package = input
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let resolve_args = adb_arguments(
        Some(serial),
        &[
            "shell",
            "cmd",
            "package",
            "resolve-activity",
            "--brief",
            "-c",
            "android.intent.category.LAUNCHER",
            package,
        ],
    );
    let resolved = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &resolve_args,
        Context::limits(SHELL_TIMEOUT_MS, PM_PATH_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    let Some(component) = parse_resolve_activity_output(&resolved.stdout) else {
        return Err(AnalysisError::unsupported_target(
            ctx.operation,
            serial,
            format!("No launcher activity is declared for {package}"),
        ));
    };
    let result_fields = json!({
        "client": ctx.client,
        "serial": serial,
        "package_name": package,
        "component": component,
    });
    run_am_start(ctx, input, serial, &["-n", &component], result_fields)
}

/// `startActivity(...)`.
pub(crate) fn start_activity(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let action = input
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let data_uri = input.get("data_uri").and_then(Value::as_str);
    let component = input.get("component").and_then(Value::as_str);
    let extras = input
        .get("extras")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Zod refinements the JSON Schema cannot express: typed extra values.
    let boolean_re = boolean_regex();
    let integer_re = integer_regex();
    let float_re = float_regex();
    for extra in &extras {
        let key = extra.get("key").and_then(Value::as_str).unwrap_or_default();
        let kind = extra
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value = extra
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let invalid = match kind {
            "boolean" if !boolean_re.is_match(value) => {
                Some(format!("Boolean extra {key} must be true or false"))
            }
            "int" if !integer_re.is_match(value) => {
                Some(format!("Integer extra {key} must be an integer"))
            }
            "long" if !integer_re.is_match(value) => {
                Some(format!("Long extra {key} must be an integer"))
            }
            "float" if !float_re.is_match(value) => {
                Some(format!("Float extra {key} must be a number"))
            }
            _ => None,
        };
        if let Some(message) = invalid {
            return Err(AnalysisError::input(
                ctx.operation,
                vec![InputIssue::new(&[], "custom", message)],
            ));
        }
    }

    let mut args: Vec<String> = vec!["-a".to_owned(), action.to_owned()];
    if let Some(data_uri) = data_uri {
        args.push("-d".to_owned());
        args.push(data_uri.to_owned());
    }
    if let Some(component) = component {
        args.push("-n".to_owned());
        args.push(component.to_owned());
    }
    for extra in &extras {
        let kind = extra
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let key = extra.get("key").and_then(Value::as_str).unwrap_or_default();
        let value = extra
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let flag = match kind {
            "string" => "--es",
            "boolean" => "--ez",
            "int" => "--ei",
            "long" => "--el",
            "float" => "--ef",
            _ => "--es",
        };
        args.push(flag.to_owned());
        args.push(key.to_owned());
        args.push(value.to_owned());
    }
    let extras_json: Vec<Value> = extras
        .iter()
        .map(|extra| {
            json!({
                "key": extra.get("key").cloned().unwrap_or(Value::Null),
                "type": extra.get("type").cloned().unwrap_or(Value::Null),
                "value": extra.get("value").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let result_fields = json!({
        "client": ctx.client,
        "serial": serial,
        "action": action,
        "data_uri": data_uri,
        "component": component,
        "extras": extras_json,
    });
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_am_start(ctx, input, serial, &args_ref, result_fields)
}

fn boolean_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(true|false)$").unwrap())
}

fn integer_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^-?\d+$").unwrap())
}

fn float_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^-?\d+(\.\d+)?$").unwrap())
}

fn run_am_start(
    ctx: &Context<'_>,
    input: &Value,
    serial: &str,
    arguments: &[&str],
    result_fields: Value,
) -> Result<Evidence, AnalysisError> {
    let mut shell_args: Vec<&str> = vec!["shell", "am", "start", "-W"];
    shell_args.extend_from_slice(arguments);
    let args = adb_arguments(Some(serial), &shell_args);
    let started = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(SHELL_TIMEOUT_MS, PM_PATH_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    let verdict = parse_am_start_output(&started.stdout, &started.stderr);
    let mut result = result_fields;
    if let Value::Object(map) = &mut result {
        map.insert("started_activity".into(), json!(verdict.started_activity));
        map.insert("reported_activity".into(), json!(verdict.activity));
        map.insert("reported_status".into(), json!(verdict.reported_status));
    }
    if verdict.status == "refused" {
        let partial = json!({
            "provider_id": "adb",
            "operation": ctx.operation,
            "result": result,
        });
        return Err(AnalysisError::unsupported_target(
            ctx.operation,
            serial,
            verdict
                .reason
                .unwrap_or_else(|| "am start refused the intent".to_owned()),
        )
        .with_captured_output(CapturedOutput {
            stdout: started.stdout.clone(),
            stderr: started.stderr.clone(),
            truncated: false,
            stdout_bytes: None,
            stderr_bytes: None,
            exit_code: None,
            signal: None,
        })
        .retain_partial_observation(partial));
    }
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Starting an activity changes device state; am start -W waits for launch completion but no lifecycle observation is captured".to_owned(),
        ],
        Some(json!({ "stdout": started.stdout, "stderr": started.stderr })),
    )
}

/// `stopApp(...)`.
pub(crate) fn stop_app(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let package = input
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = adb_arguments(Some(serial), &["shell", "am", "force-stop", package]);
    run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(SHELL_TIMEOUT_MS, PM_PATH_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "package_name": package,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Force-stop succeeds even for packages with no running process; it reports completion, not prior state".to_owned(),
        ],
        None,
    )
}
