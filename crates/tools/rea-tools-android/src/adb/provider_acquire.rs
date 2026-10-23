//! Acquisition ADB operations: pulls, screen capture and bugreport collection.
//!
//! Compatibility owner: the `pullFile`, `pullPackage`, `captureScreen` and
//! `collectBugreport` methods of `AdbProvider`.
//!
//! Native digest note: `common::files::hash_stable_file` reads through one
//! descriptor that Rust closes on drop, so the TS "digest handle could not be
//! closed" cleanup-lease path cannot occur here. A digest failure is a plain
//! output error (or cancellation) with the acquired-file partial observation
//! retained; see the family report.
use crate::adb::command::{AdbCommandTarget, adb_arguments, run_adb, run_adb_capture};
use crate::adb::device_output::{display_device_path, parse_pm_path_output};
use crate::adb::files::{
    self, OutputDirectoryIdentity, prepare_output_directory, refuse_existing_target, resolve_path,
};
use crate::adb::provider::{
    BUGREPORT_MAX_OUTPUT_BYTES, BUGREPORT_TIMEOUT_MS, Context, PM_PATH_MAX_OUTPUT_BYTES,
    PM_PATH_TIMEOUT_MS, PULL_MAX_OUTPUT_BYTES, PULL_TIMEOUT_MS, SCREEN_MAX_OUTPUT_BYTES,
    SCREEN_TIMEOUT_MS, finish, parameters, serial_of,
};
use crate::adb::shell_output::{parse_bugreport_copied_path, parse_png_dimensions};
use crate::adb::state::PendingOutputDirectory;
use crate::common::files::hash_stable_file;
use crate::common::workspace::PrivateRoot;
use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::evidence::envelope::Evidence;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

fn digest_file(
    path: &Path,
    operation: &str,
    cancellation: &rea_core::cancellation::Cancellation,
) -> Result<crate::common::files::FileDigest, AnalysisError> {
    hash_stable_file(path, cancellation).map_err(|error| match error {
        crate::common::files::StableFileError::Cancelled(_) => AnalysisError::cancelled(operation),
        other => AnalysisError::output(
            operation,
            format!(
                "The pulled file could not be read back after pulling: {}: {}",
                path.display(),
                other
            ),
        ),
    })
}

/// `pullFile(...)`.
pub(crate) fn pull_file(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let device_path = input
        .get("device_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let output_directory = input
        .get("output_directory")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let derived = crate::adb::host_file_name::adb_host_file_name(device_path).map_err(|reason| {
        AnalysisError::input(
            ctx.operation,
            vec![rea_core::analysis_error::InputIssue::new(
                &["device_path"],
                "invalid_value",
                format!(
                    "The device path {} does not name a file that can be written on this host ({}); REA never renames a device-reported file.",
                    serde_json::to_string(device_path).unwrap_or_default(),
                    reason.as_str()
                ),
            )],
        )
    })?;
    let directory = prepare_output_directory(ctx.operation, output_directory)?;
    let local_path = Path::new(&directory).join(&derived);
    if let Some(error) = refuse_existing_target(ctx.operation, &local_path) {
        return Err(error);
    }
    let local_path_str = local_path.to_string_lossy().into_owned();
    let args = adb_arguments(Some(serial), &["pull", device_path, &local_path_str]);
    run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: Some(device_path.to_owned()),
            local_path: Some(local_path_str.clone()),
        },
        &ctx.selection.binary,
        &args,
        Context::limits(PULL_TIMEOUT_MS, PULL_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;

    match digest_file(&local_path, ctx.operation, ctx.cancellation) {
        Ok(digest) => {
            let result = json!({
                "client": ctx.client,
                "serial": serial,
                "device_path": device_path,
                "local_path": local_path_str,
                "bytes": digest.bytes,
                "sha256": digest.sha256,
            });
            finish(
                ctx,
                parameters(input),
                result,
                vec![
                    "The pulled file is a host-local copy; the device retains the original"
                        .to_owned(),
                ],
                None,
            )
        }
        Err(error) => {
            let partial = json!({
                "provider_id": "adb",
                "operation": ctx.operation,
                "result": {
                    "client": ctx.client,
                    "serial": serial,
                    "local_path": local_path_str,
                    "device_path": device_path,
                    "digest_status": "unknown",
                },
            });
            Err(error.retain_partial_observation(partial))
        }
    }
}

/// `pullPackage(...)`.
pub(crate) fn pull_package(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let package = input
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let output_directory = input
        .get("output_directory")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let paths_args = adb_arguments(Some(serial), &["shell", "pm", "path", package]);
    let paths = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &paths_args,
        Context::limits(PM_PATH_TIMEOUT_MS, PM_PATH_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    let parsed = parse_pm_path_output(&paths.stdout);
    let captured_output = CapturedOutput {
        stdout: paths.stdout.clone(),
        stderr: paths.stderr.clone(),
        truncated: false,
        stdout_bytes: None,
        stderr_bytes: None,
        exit_code: None,
        signal: None,
    };

    if !parsed.rejected_paths.is_empty() {
        let first = &parsed.rejected_paths[0];
        let other_count = parsed.rejected_paths.len() - 1;
        let others = if other_count > 0 {
            format!(" and {other_count} other path(s)")
        } else {
            String::new()
        };
        let rejected: Vec<Value> = parsed
            .rejected_paths
            .iter()
            .map(|rejected| {
                json!({ "device_path": rejected.device_path, "reason": rejected.reason.as_str() })
            })
            .collect();
        return Err(AnalysisError::output(ctx.operation, "unsafe_device_path")
            .with_captured_output(captured_output)
            .with_user_message(format!(
                "pm path for {package} reported an APK path that cannot be written as a file on this host: {} ({}){others}. No APK was pulled.",
                display_device_path(&first.device_path),
                first.reason.as_str(),
            ))
            .with_remediation(
                "Review details.diagnostics for the refused device paths and details.captured_output for the retained pm path output. REA does not rename device-reported APK paths; correct the device path policy before retrying.",
            )
            .with_diagnostics(crate::common::errors::object(json!({
                "package_name": package,
                "rejected_paths": rejected,
            }))));
    }
    if parsed.paths.is_empty() && parsed.unparsed_lines.is_empty() {
        return Err(AnalysisError::unsupported_target(
            ctx.operation,
            serial,
            format!(
                "Package Manager reported no APK paths for {package}; it may not be installed for user 0"
            ),
        ));
    }
    if !parsed.unparsed_lines.is_empty() {
        return Err(AnalysisError::protocol(format!(
            "pm path reported an unrecognized line: {}",
            parsed.unparsed_lines[0]
        ))
        .with_captured_output(captured_output));
    }
    // Reject duplicate local destinations.
    let mut seen: Vec<&str> = Vec::new();
    for entry in &parsed.paths {
        if seen.contains(&entry.file_name.as_str()) {
            let device_paths: Vec<Value> = parsed
                .paths
                .iter()
                .filter(|candidate| candidate.file_name == entry.file_name)
                .map(|candidate| json!(candidate.device_path))
                .collect();
            return Err(AnalysisError::output(ctx.operation, "duplicate_local_destination")
                .with_captured_output(captured_output)
                .with_user_message(format!(
                    "pm path for {package} reported multiple APK paths with the same local file name {}; no APK was pulled.",
                    display_device_path(&entry.file_name)
                ))
                .with_remediation(
                    "Review details.diagnostics and details.captured_output for the conflicting device paths. REA does not rename device-reported paths; correct Package Manager's path response before retrying.",
                )
                .with_diagnostics(crate::common::errors::object(json!({
                    "package_name": package,
                    "file_name": entry.file_name,
                    "device_paths": device_paths,
                }))));
        }
        seen.push(entry.file_name.as_str());
    }

    let directory = prepare_output_directory(ctx.operation, output_directory)?;
    let package_directory = Path::new(&directory).join(package);
    let package_directory_str = package_directory.to_string_lossy().into_owned();
    let identity = match files::create_directory_with_identity(&package_directory) {
        Ok(identity) => identity,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(AnalysisError::output(ctx.operation, error.to_string()));
            }
            // The directory may have been created; retain for cleanup retry.
            let primary = AnalysisError::output(
                ctx.operation,
                "Could not establish an owned package directory identity",
            );
            ctx.state.retain_directory(PendingOutputDirectory {
                path: package_directory_str.clone(),
                identity: None,
                primary: primary.clone(),
            });
            let cleanup = crate::common::errors::provider_cleanup(
                crate::adb::provider::ADB_PROVIDER_ID,
                ctx.operation,
                vec![package_directory_str.clone()],
                crate::common::errors::object(json!({
                    "reason": "Could not establish an owned package directory identity",
                })),
            );
            return Err(crate::common::errors::with_cleanup_failure(
                primary,
                cleanup,
                ctx.operation,
            ));
        }
    };

    let fail_owned = |ctx: &Context<'_>, primary: AnalysisError| -> AnalysisError {
        match files::remove_owned_output_directory(&package_directory_str, Some(identity)) {
            Ok(()) => primary,
            Err(reason) => {
                ctx.state.retain_directory(PendingOutputDirectory {
                    path: package_directory_str.clone(),
                    identity: Some(identity),
                    primary: primary.clone(),
                });
                let cleanup = crate::common::errors::provider_cleanup(
                    crate::adb::provider::ADB_PROVIDER_ID,
                    ctx.operation,
                    vec![package_directory_str.clone()],
                    crate::common::errors::object(json!({ "reason": reason })),
                );
                crate::common::errors::with_cleanup_failure(primary, cleanup, ctx.operation)
            }
        }
    };

    // Reserve destinations.
    let entries: Vec<(String, String)> = parsed
        .paths
        .iter()
        .map(|entry| (entry.file_name.clone(), entry.device_path.clone()))
        .collect();
    if let Some(error) = files::reserve_package_destinations(
        ctx.operation,
        package,
        &package_directory,
        &entries,
        captured_output.clone(),
    ) {
        return Err(fail_owned(ctx, error));
    }

    let mut artifacts: Vec<Value> = Vec::new();
    let mut failures: Vec<Value> = Vec::new();

    for entry in &parsed.paths {
        let local_path = package_directory.join(&entry.file_name);
        let local_path_str = local_path.to_string_lossy().into_owned();
        let pull_args = adb_arguments(Some(serial), &["pull", &entry.device_path, &local_path_str]);
        let pulled = run_adb(
            ctx.operation,
            &AdbCommandTarget {
                device: serial.to_owned(),
                path: Some(entry.device_path.clone()),
                local_path: Some(local_path_str.clone()),
            },
            &ctx.selection.binary,
            &pull_args,
            Context::limits(PULL_TIMEOUT_MS, PULL_MAX_OUTPUT_BYTES),
            ctx.cancellation,
        );
        if let Err(command_error) = pulled {
            let error = ctx.retain_child(command_error);
            if matches!(
                error.kind,
                rea_core::analysis_error::ErrorKind::Cancelled { .. }
            ) {
                return Err(cancelled_package_pull(
                    ctx,
                    error,
                    serial,
                    package,
                    &directory,
                    &artifacts,
                    &failures,
                    &entry.device_path,
                    &local_path_str,
                    "pull",
                ));
            }
            failures.push(json!({
                "device_path": entry.device_path,
                "stage": "pull",
                "message": error.message(),
            }));
            continue;
        }
        match digest_file(&local_path, ctx.operation, ctx.cancellation) {
            Ok(digest) => {
                artifacts.push(json!({
                    "device_path": entry.device_path,
                    "file_name": entry.file_name,
                    "local_path": local_path_str,
                    "bytes": digest.bytes,
                    "sha256": digest.sha256,
                    "role": entry.role,
                    "role_basis": "file_name",
                }));
            }
            Err(error) => {
                if matches!(
                    error.kind,
                    rea_core::analysis_error::ErrorKind::Cancelled { .. }
                ) {
                    return Err(cancelled_package_pull(
                        ctx,
                        error,
                        serial,
                        package,
                        &directory,
                        &artifacts,
                        &failures,
                        &entry.device_path,
                        &local_path_str,
                        "digest",
                    ));
                }
                failures.push(json!({
                    "device_path": entry.device_path,
                    "stage": "digest",
                    "message": error.message(),
                }));
            }
        }
    }

    if artifacts.is_empty() && !failures.is_empty() {
        let first_message = failures[0]
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let primary = AnalysisError::protocol(format!(
            "Every APK pull failed for {package} on {serial}: {first_message}"
        ));
        return Err(fail_owned(ctx, primary));
    }

    let coverage = if failures.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "package_name": package,
        "output_directory": directory,
        "artifacts": artifacts,
        "failures": failures,
        "coverage": coverage,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "APK role names derive from the pulled file names (base.apk, split_*.apk)".to_owned(),
            "Pulled artifacts are host-local copies; the device retains the originals".to_owned(),
        ],
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn cancelled_package_pull(
    ctx: &Context<'_>,
    error: AnalysisError,
    serial: &str,
    package: &str,
    directory: &str,
    artifacts: &[Value],
    failures: &[Value],
    device_path: &str,
    local_path: &str,
    stage: &str,
) -> AnalysisError {
    let message = if stage == "pull" {
        format!(
            "Pull cancelled; any incomplete file is retained at {local_path}. Remaining APKs were not attempted."
        )
    } else {
        format!(
            "Digesting the pulled file was cancelled; the file is retained at {local_path}. Remaining APKs were not attempted."
        )
    };
    let mut all_failures: Vec<Value> = failures.to_vec();
    all_failures.push(json!({
        "device_path": device_path,
        "stage": stage,
        "message": message,
    }));
    let partial = json!({
        "provider_id": "adb",
        "operation": "pull_adb_package",
        "result": {
            "client": ctx.client,
            "serial": serial,
            "package_name": package,
            "output_directory": directory,
            "artifacts": artifacts,
            "failures": all_failures,
            "coverage": "partial",
        },
    });
    error.retain_partial_observation(partial)
}

/// `captureScreen(...)`.
pub(crate) fn capture_screen(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let output_directory = input
        .get("output_directory")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let directory = prepare_output_directory(ctx.operation, output_directory)?;
    let local_path = Path::new(&directory).join("screen.png");
    if let Some(error) = refuse_existing_target(ctx.operation, &local_path) {
        return Err(error);
    }
    let args = adb_arguments(Some(serial), &["exec-out", "screencap", "-p"]);
    let captured = run_adb_capture(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(SCREEN_TIMEOUT_MS, SCREEN_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    if ctx.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(ctx.operation));
    }
    let (width, height) = parse_png_dimensions(&captured.stdout);
    let Some(width) = width else {
        return Err(AnalysisError::protocol(
            "screencap did not return a PNG payload; the device may not expose a display",
        ));
    };

    // Stage in a private child directory, then publish by hard link, falling
    // back to exclusive create when hard links are unsupported.
    let mut root = PrivateRoot::create(Path::new(&directory), ".rea-screen-").map_err(|error| {
        AnalysisError::output(ctx.operation, "Could not create an ADB private workspace")
            .with_diagnostics(crate::common::errors::object(
                json!({ "io_error": error.to_string() }),
            ))
    })?;
    let mut used_exclusive_fallback = false;
    let publication = (|| -> Result<(), AnalysisError> {
        let staged_path = root.path().join("screen.png");
        crate::common::files::write_new_file(&staged_path, &captured.stdout)
            .map_err(|error| AnalysisError::output(ctx.operation, error.to_string()))?;
        if ctx.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(ctx.operation));
        }
        match std::fs::hard_link(&staged_path, &local_path) {
            Ok(()) => Ok(()),
            Err(error) if hard_links_unsupported(&error) => {
                used_exclusive_fallback = true;
                crate::common::files::write_new_file(&local_path, &captured.stdout).map_err(
                    |cause| {
                        AnalysisError::output(
                            ctx.operation,
                            format!(
                                "The screen output could not be published exclusively: {}",
                                local_path.display()
                            ),
                        )
                        .with_diagnostics(crate::common::errors::object(
                            json!({
                                "io_error": cause.to_string(),
                            }),
                        ))
                    },
                )
            }
            Err(error) => Err(AnalysisError::output(ctx.operation, error.to_string())),
        }
    })();
    let _ = root.close();
    publication?;

    let sha256 = format!("{:x}", Sha256::digest(&captured.stdout));
    let mut limitations = vec![
        "The capture is one frame at read time; no recording or interaction occurred".to_owned(),
    ];
    if used_exclusive_fallback {
        limitations.push(
            "The exclusive-create fallback makes the output path visible while its bytes are being written".to_owned(),
        );
    }
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "local_path": local_path.to_string_lossy(),
        "bytes": captured.stdout.len(),
        "sha256": sha256,
        "width": width,
        "height": height,
    });
    finish(ctx, parameters(input), result, limitations, None)
}

fn hard_links_unsupported(error: &std::io::Error) -> bool {
    crate::common::files::io_code(error)
        .map(|code| {
            matches!(
                code,
                "EPERM" | "EOPNOTSUPP" | "ENOTSUP" | "ENOSYS" | "EXDEV"
            )
        })
        .unwrap_or(false)
}

/// `collectBugreport(...)`.
pub(crate) fn collect_bugreport(
    ctx: &Context<'_>,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let output_directory = input
        .get("output_directory")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let directory = prepare_output_directory(ctx.operation, output_directory)?;

    let staging = create_staging_directory(Path::new(&directory)).map_err(|_| {
        AnalysisError::output(
            ctx.operation,
            "The bugreport staging directory could not be created",
        )
    })?;
    let staging_str = staging.to_string_lossy().into_owned();
    let staging_identity = match std::fs::symlink_metadata(&staging) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Some(identity_of(&metadata))
        }
        _ => None,
    };

    let mut published_path: Option<String> = None;
    let mut retained: Option<Value> = None;
    let collected = collect_into_staging(
        ctx,
        serial,
        &directory,
        &staging,
        &mut published_path,
        &mut retained,
    );

    // A completed acquisition becomes caller evidence even if cleanup is
    // pending; its staging directory must not be removed yet.
    if retained.is_some() && published_path.is_none() {
        return collected;
    }
    match files::remove_owned_output_directory(&staging_str, staging_identity) {
        Ok(()) => collected,
        Err(reason) => {
            let primary = match &collected {
                Ok(_) => AnalysisError::output(
                    ctx.operation,
                    "The archive was published, but its staging directory could not be removed",
                ),
                Err(error) => error.clone(),
            };
            let primary = match &retained {
                Some(observation) => primary.retain_partial_observation(observation.clone()),
                None => primary,
            };
            ctx.state.retain_directory(PendingOutputDirectory {
                path: staging_str.clone(),
                identity: staging_identity,
                primary: primary.clone(),
            });
            let cleanup = crate::common::errors::provider_cleanup(
                crate::adb::provider::ADB_PROVIDER_ID,
                ctx.operation,
                vec![staging_str.clone()],
                crate::common::errors::object(json!({ "reason": reason })),
            );
            Err(crate::common::errors::with_cleanup_failure(
                primary,
                cleanup,
                ctx.operation,
            ))
        }
    }
}

fn collect_into_staging(
    ctx: &Context<'_>,
    serial: &str,
    directory: &str,
    staging: &Path,
    published_path: &mut Option<String>,
    retained: &mut Option<Value>,
) -> Result<Evidence, AnalysisError> {
    let staging_str = staging.to_string_lossy().into_owned();
    let args = adb_arguments(Some(serial), &["bugreport", &staging_str]);
    let collected = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(BUGREPORT_TIMEOUT_MS, BUGREPORT_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;

    let Some(reported_path) = parse_bugreport_copied_path(&collected.stdout) else {
        return Err(AnalysisError::protocol(
            "adb bugreport did not report an archive path; the build may use an unsupported format",
        ));
    };
    let resolved = resolve_path(&reported_path);
    if resolved.parent() != Some(staging) {
        return Err(AnalysisError::protocol(format!(
            "adb bugreport reported an archive outside its staging directory: {reported_path}"
        )));
    }
    let archive = std::fs::symlink_metadata(&reported_path)
        .map_err(|error| AnalysisError::output(ctx.operation, error.to_string()))?;
    if !archive.is_file() || archive.file_type().is_symlink() {
        return Err(AnalysisError::protocol(format!(
            "adb bugreport did not report a regular archive file: {reported_path}"
        )));
    }
    *retained = Some(json!({
        "provider_id": "adb",
        "operation": "collect_adb_bugreport",
        "result": {
            "client": ctx.client,
            "serial": serial,
            "local_path": reported_path,
            "adb_reported_path": reported_path,
            "digest_status": "unknown",
        },
    }));
    let published = files::publish_bugreport(&reported_path, directory).map_err(|error| {
        let mut err = AnalysisError::output(
            ctx.operation,
            format!("The reported bugreport archive could not be published: {reported_path}"),
        )
        .with_diagnostics(crate::common::errors::object(
            json!({ "io_error": error.to_string() }),
        ));
        if let Some(observation) = retained.as_ref() {
            err = err.retain_partial_observation(observation.clone());
        }
        err
    })?;
    *published_path = Some(published.clone());
    *retained = Some(json!({
        "provider_id": "adb",
        "operation": "collect_adb_bugreport",
        "result": {
            "client": ctx.client,
            "serial": serial,
            "local_path": published,
            "adb_reported_path": reported_path,
            "digest_status": "unknown",
        },
    }));
    match digest_file(Path::new(&published), ctx.operation, ctx.cancellation) {
        Ok(digest) => {
            let report = json!({
                "client": ctx.client,
                "serial": serial,
                "local_path": published,
                "bytes": digest.bytes,
                "sha256": digest.sha256,
                "adb_reported_path": reported_path,
            });
            *retained = Some(json!({
                "provider_id": "adb",
                "operation": "collect_adb_bugreport",
                "result": report.clone(),
            }));
            finish(
                ctx,
                parameters_for_bugreport(serial, directory),
                report,
                vec![
                    "The archive is device-generated: dumpstate, dumpsys, and logcat content is the device's own report".to_owned(),
                ],
                None,
            )
        }
        Err(error) => {
            let error = match retained.as_ref() {
                Some(observation) => error.retain_partial_observation(observation.clone()),
                None => error,
            };
            Err(error)
        }
    }
}

fn parameters_for_bugreport(serial: &str, directory: &str) -> Value {
    json!({ "serial": serial, "output_directory": directory })
}

fn create_staging_directory(parent: &Path) -> std::io::Result<std::path::PathBuf> {
    for _ in 0..1024 {
        let candidate = parent.join(format!(
            ".rea-bugreport-{}",
            crate::common::ids::random_hex(6)
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::other(
        "could not allocate a staging directory",
    ))
}

#[cfg(unix)]
fn identity_of(metadata: &std::fs::Metadata) -> OutputDirectoryIdentity {
    use std::os::unix::fs::MetadataExt;
    OutputDirectoryIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
    }
}

#[cfg(windows)]
fn identity_of(_metadata: &std::fs::Metadata) -> OutputDirectoryIdentity {
    OutputDirectoryIdentity {
        dev: 0,
        ino: 0,
        mode: 0,
    }
}
