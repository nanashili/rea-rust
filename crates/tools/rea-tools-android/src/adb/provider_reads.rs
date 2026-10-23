//! Read-only ADB operations.
//!
//! Compatibility owner: the read-only cases of `AdbProvider.#executeOperation`.
use crate::adb::command::{AdbCommandTarget, adb_arguments, run_adb};
use crate::adb::device_output::{
    parse_adb_devices_output, parse_getprop_output, parse_package_list_output,
};
use crate::adb::directory_listing::{ADB_DIRECTORY_BATCH_SCRIPT, parse_adb_directory_listing};
use crate::adb::provider::{
    self, Context, DEVICES_MAX_OUTPUT_BYTES, DEVICES_TIMEOUT_MS, DUMPSYS_PACKAGE_MAX_OUTPUT_BYTES,
    DUMPSYS_PACKAGE_TIMEOUT_MS, DUMPSYS_WINDOW_MAX_OUTPUT_BYTES, GETPROP_MAX_OUTPUT_BYTES,
    LISTING_MAX_OUTPUT_BYTES, LISTING_TIMEOUT_MS, LOGCAT_MAX_OUTPUT_BYTES, LOGCAT_TIMEOUT_MS,
    PACKAGE_LIST_MAX_OUTPUT_BYTES, PACKAGE_LIST_TIMEOUT_MS, SETTINGS_MAX_OUTPUT_BYTES,
    SETTINGS_TIMEOUT_MS, SHELL_TIMEOUT_MS, finish, parameters, serial_of,
};
use crate::adb::shell_output::{
    parse_dumpsys_package_output, parse_feature_list_output, parse_process_list_output,
    parse_service_list_output, parse_settings_get_output, parse_window_focus_output,
    parse_wm_density_output, parse_wm_size_output,
};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use serde_json::{Value, json};

fn device_entries_json(devices: &[crate::adb::device_output::AdbDeviceEntry]) -> Value {
    Value::Array(
        devices
            .iter()
            .map(|device| {
                json!({
                    "serial": device.serial,
                    "state": device.state,
                    "transport": device.transport,
                    "product": device.product,
                    "model": device.model,
                    "device": device.device,
                    "transport_id": device.transport_id,
                    "kind": device.kind,
                    "kind_basis": device.kind_basis,
                })
            })
            .collect(),
    )
}

pub(crate) fn list_devices(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let args = vec!["devices".to_owned(), "-l".to_owned()];
    let ran = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: "adb-devices".to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(DEVICES_TIMEOUT_MS, DEVICES_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    let parsed = parse_adb_devices_output(&ran.stdout, &ran.stderr);
    if !parsed.unparsed_lines.is_empty() {
        return Err(AnalysisError::protocol(format!(
            "adb devices reported an unrecognized line: {}",
            parsed.unparsed_lines[0]
        )));
    }
    let result = json!({
        "client": ctx.client,
        "devices": device_entries_json(&parsed.devices),
        "may_have_started_adb_server": parsed.daemon_started,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Device kind is inferred from the emulator serial prefix and USB transport metadata, not from device attestation".to_owned(),
            "Kind stays unknown for TCP transports unless the serial is an emulator port".to_owned(),
        ],
        None,
    )
}

pub(crate) fn inspect_device(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let args = adb_arguments(Some(serial), &["shell", "getprop"]);
    let ran = run_adb(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: None,
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(SHELL_TIMEOUT_MS, GETPROP_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    let parsed = parse_getprop_output(&ran.stdout);
    let properties: Vec<Value> = parsed
        .properties
        .iter()
        .map(|property| json!({ "name": property.name, "value": property.value }))
        .collect();
    let property_count = properties.len();
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "properties": properties,
        "property_count": property_count,
        "emulator_observed": parsed.emulator_observed,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Properties are a fixed whitelist of build identity facts, not the full getprop dump"
                .to_owned(),
            "emulator_observed is null when the build does not report ro.kernel.qemu".to_owned(),
        ],
        None,
    )
}

pub(crate) fn list_packages(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let scope = input.get("scope").and_then(Value::as_str).unwrap_or("all");
    let scope_flag = match scope {
        "third_party" => Some("-3"),
        "system" => Some("-s"),
        _ => None,
    };
    let mut args = vec!["pm", "list", "packages", "-f"];
    if let Some(flag) = scope_flag {
        args.push(flag);
    }
    let ran = ctx
        .shell(
            serial,
            &args,
            Context::limits(PACKAGE_LIST_TIMEOUT_MS, PACKAGE_LIST_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let (packages, unparsed) = parse_package_list_output(&ran.stdout);
    let (capped, coverage) = provider::reported(&unparsed, "complete");
    let packages_json: Vec<Value> = packages
        .iter()
        .map(|entry| {
            json!({
                "package_name": entry.package_name,
                "base_apk_device_path": entry.base_apk_device_path,
            })
        })
        .collect();
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "scope": scope,
        "packages": packages_json,
        "unparsed_lines": capped,
        "coverage": coverage,
    });
    let mut limitations =
        vec!["base_apk_device_path is a device filesystem path, not a host-local path".to_owned()];
    limitations.extend(provider::unparsed_overflow_limitation(&unparsed));
    finish(ctx, parameters(input), result, limitations, None)
}

pub(crate) fn read_logcat(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let count = input.get("count").and_then(Value::as_i64).unwrap_or(500);
    let buffer = input
        .get("buffer")
        .and_then(Value::as_str)
        .unwrap_or("main");
    let pid = input.get("pid").and_then(Value::as_i64);
    let count_text = count.to_string();
    let pid_text = pid.map(|value| value.to_string());
    let mut args = vec!["logcat", "-d", "-b", buffer, "-t", &count_text];
    if let Some(pid_text) = pid_text.as_deref() {
        args.push("--pid");
        args.push(pid_text);
    }
    let ran = ctx
        .shell(
            serial,
            &args,
            Context::limits(LOGCAT_TIMEOUT_MS, LOGCAT_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let mut lines: Vec<String> = ran
        .stdout
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_owned())
        .collect();
    if lines.last().map(String::as_str) == Some("") {
        lines.pop();
    }
    let total = lines.len();
    let want = count.max(0) as usize;
    let bounded: Vec<String> = if lines.len() > want {
        lines[lines.len() - want..].to_vec()
    } else {
        lines.clone()
    };
    let coverage = if bounded.len() != total || bounded.len() == want {
        "partial"
    } else {
        "complete"
    };
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "count": count,
        "buffer": buffer,
        "pid": pid,
        "lines": bounded,
        "total_bytes": ran.stdout_bytes,
        "coverage": coverage,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Reads a bounded dump (logcat -d); the newest lines are kept when the count cap trims"
                .to_owned(),
            "coverage is partial when the requested count or capture budget truncated the dump"
                .to_owned(),
        ],
        None,
    )
}

pub(crate) fn inspect_package(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let package = input
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ran = ctx
        .shell(
            serial,
            &["dumpsys", "package", package],
            Context::limits(DUMPSYS_PACKAGE_TIMEOUT_MS, DUMPSYS_PACKAGE_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    if ran.stdout.contains("Unable to find package:") || ran.stdout.trim().is_empty() {
        return Err(AnalysisError::unsupported_target(
            ctx.operation,
            serial,
            format!(
                "Package Manager did not report details for {package}; it may not be installed for user 0"
            ),
        ));
    }
    let details = parse_dumpsys_package_output(&ran.stdout);
    let coverage = if details.requested_permissions.is_none()
        || (details.version_code.is_none() && details.version_name.is_none())
    {
        "partial"
    } else {
        "complete"
    };
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "package_name": package,
        "version_name": details.version_name,
        "version_code": details.version_code,
        "first_install_time": details.first_install_time,
        "last_update_time": details.last_update_time,
        "installer_package_name": details.installer_package_name,
        "user_id": details.user_id,
        "pkg_flags": details.pkg_flags,
        "requested_permissions_count": details.requested_permissions,
        "coverage": coverage,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Fields are a fixed projection of dumpsys package output; version-dependent sections are ignored rather than guessed".to_owned(),
            "requested_permissions_count counts the listed requested permissions section; an absent section is zero only when dumpsys confirms a loaded parsed package".to_owned(),
            "A null requested_permissions_count means dumpsys reported pkg=null or did not establish that an omitted permission section is an empty inventory".to_owned(),
        ],
        None,
    )
}

pub(crate) fn list_processes(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let ran = ctx
        .shell(
            serial,
            &["ps", "-A"],
            Context::limits(LISTING_TIMEOUT_MS, LISTING_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let parsed = parse_process_list_output(&ran.stdout);
    let (capped, coverage) = provider::reported(&parsed.unparsed_lines, "complete");
    let processes: Vec<Value> = parsed
        .processes
        .iter()
        .map(|process| {
            json!({
                "user": process.user,
                "pid": process.pid,
                "ppid": process.ppid,
                "rss": process.rss,
                "state": process.state,
                "name": process.name,
            })
        })
        .collect();
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "columns": parsed.columns,
        "processes": processes,
        "unparsed_lines": capped,
        "coverage": coverage,
    });
    finish(
        ctx,
        parameters(input),
        result,
        provider::unparsed_overflow_limitation(&parsed.unparsed_lines),
        None,
    )
}

pub(crate) fn list_directory(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let device_path = input
        .get("device_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = adb_arguments(
        Some(serial),
        &[
            "shell",
            "sh",
            "-c",
            "cd \"$1\" || exit\nexec find . -mindepth 1 -maxdepth 1 -exec sh -c \"$2\" rea-list-directory {} +",
            "rea-list-directory",
            device_path,
            ADB_DIRECTORY_BATCH_SCRIPT,
        ],
    );
    let ran = crate::adb::command::run_adb_capture(
        ctx.operation,
        &AdbCommandTarget {
            device: serial.to_owned(),
            path: Some(device_path.to_owned()),
            local_path: None,
        },
        &ctx.selection.binary,
        &args,
        Context::limits(LISTING_TIMEOUT_MS, LISTING_MAX_OUTPUT_BYTES),
        ctx.cancellation,
    )
    .map_err(|error| ctx.retain_child(error))?;
    let parsed = parse_adb_directory_listing(&ran.stdout);
    let (capped, coverage) = provider::reported(&parsed.unparsed_lines, "complete");
    let entries: Vec<Value> = parsed
        .entries
        .iter()
        .map(|entry| {
            json!({
                "name": entry.name,
                "kind": entry.kind,
                "permissions": entry.permissions,
                "owner": entry.owner,
                "group": entry.group,
                "bytes": entry.bytes,
                "date": entry.date,
                "link_target": entry.link_target,
            })
        })
        .collect();
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "device_path": device_path,
        "entries": entries,
        "unparsed_lines": capped,
        "coverage": coverage,
    });
    let mut limitations = vec![
        "Entry kinds derive from stat permission mode; directory contents and link targets may change during capture".to_owned(),
    ];
    limitations.extend(provider::unparsed_overflow_limitation(
        &parsed.unparsed_lines,
    ));
    finish(ctx, parameters(input), result, limitations, None)
}

pub(crate) fn list_features(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let ran = ctx
        .shell(
            serial,
            &["pm", "list", "features"],
            Context::limits(LISTING_TIMEOUT_MS, LISTING_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let parsed = parse_feature_list_output(&ran.stdout);
    let (capped, coverage) = provider::reported(&parsed.unparsed_lines, "complete");
    let features: Vec<Value> = parsed
        .features
        .iter()
        .map(|feature| json!({ "name": feature.name, "version": feature.version }))
        .collect();
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "features": features,
        "unparsed_lines": capped,
        "coverage": coverage,
    });
    finish(
        ctx,
        parameters(input),
        result,
        provider::unparsed_overflow_limitation(&parsed.unparsed_lines),
        None,
    )
}

pub(crate) fn list_services(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let ran = ctx
        .shell(
            serial,
            &["service", "list"],
            Context::limits(LISTING_TIMEOUT_MS, LISTING_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let parsed = parse_service_list_output(&ran.stdout);
    let (capped, coverage) = provider::reported(&parsed.unparsed_lines, "complete");
    let services: Vec<Value> = parsed
        .services
        .iter()
        .map(|service| json!({ "name": service.name, "interface": service.interface }))
        .collect();
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "services": services,
        "unparsed_lines": capped,
        "coverage": coverage,
    });
    finish(
        ctx,
        parameters(input),
        result,
        provider::unparsed_overflow_limitation(&parsed.unparsed_lines),
        None,
    )
}

pub(crate) fn inspect_display(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let size = ctx
        .shell(
            serial,
            &["wm", "size"],
            Context::limits(SETTINGS_TIMEOUT_MS, SETTINGS_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let density = ctx
        .shell(
            serial,
            &["wm", "density"],
            Context::limits(SETTINGS_TIMEOUT_MS, SETTINGS_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let (physical, override_size) = parse_wm_size_output(&size.stdout);
    let Some(physical) = physical else {
        return Err(AnalysisError::protocol(
            "wm size did not report a physical size; the build may use an unsupported format",
        ));
    };
    let (physical_density, override_density) = parse_wm_density_output(&density.stdout);
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "physical_size": { "width": physical.width, "height": physical.height },
        "override_size": override_size.map(|size| json!({ "width": size.width, "height": size.height })),
        "physical_density": physical_density,
        "override_density": override_density,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Override values are present only when a build has overridden the physical values"
                .to_owned(),
        ],
        None,
    )
}

pub(crate) fn inspect_window(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let mut section = "windows";
    let ran = ctx
        .shell(
            serial,
            &["dumpsys", "window", section],
            Context::limits(SHELL_TIMEOUT_MS, DUMPSYS_WINDOW_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let mut focus = parse_window_focus_output(&ran.stdout);
    if focus.focus_summary == "unavailable" {
        section = "displays";
        let fallback = ctx
            .shell(
                serial,
                &["dumpsys", "window", section],
                Context::limits(SHELL_TIMEOUT_MS, DUMPSYS_WINDOW_MAX_OUTPUT_BYTES),
            )
            .map_err(|error| ctx.retain_child(error))?;
        focus = parse_window_focus_output(&fallback.stdout);
    }
    let declared = focus.focus_summary != "unavailable";
    let focus_contexts: Vec<Value> = focus
        .focus_contexts
        .iter()
        .map(|context| {
            json!({
                "scope": context.scope,
                "display_id": context.display_id,
                "header_line": context.header_line,
                "declarations": context.declarations.iter().map(|declaration| json!({
                    "field": declaration.field,
                    "value": declaration.value,
                    "raw_line": declaration.raw_line,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "source_section": section,
        "focus_contexts": focus_contexts,
        "focus_summary": focus.focus_summary,
        "focused_window": focus.focused_window,
        "focused_app": focus.focused_app,
        "observed_lines": focus.observed_lines,
    });
    let mut limitations = vec![
        "Focus values are the window manager's declarations at read time; no interaction occurred"
            .to_owned(),
    ];
    if declared {
        limitations.push(format!(
            "Focus declarations were read from `dumpsys window {section}`"
        ));
    } else {
        limitations.push(
            "Neither `dumpsys window windows` nor `dumpsys window displays` declared mCurrentFocus or mFocusedApp; focus is unknown, not absent".to_owned(),
        );
    }
    if focus.focus_summary == "ambiguous" {
        limitations.push(
            "Multiple focus contexts or repeated declarations prevent a singular focus summary; inspect focus_contexts for every declaration".to_owned(),
        );
    }
    finish(ctx, parameters(input), result, limitations, None)
}

pub(crate) fn read_setting(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let namespace = input
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let key = input.get("key").and_then(Value::as_str).unwrap_or_default();
    let ran = ctx
        .shell(
            serial,
            &["settings", "get", namespace, key],
            Context::limits(SETTINGS_TIMEOUT_MS, SETTINGS_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let (value, device_reported_null) = parse_settings_get_output(&ran.stdout);
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "namespace": namespace,
        "key": key,
        "value": value,
        "device_reported_null": device_reported_null,
    });
    finish(
        ctx,
        parameters(input),
        result,
        vec![
            "Android prints the literal string null for absent keys; that is reported as a device-side null observation".to_owned(),
        ],
        None,
    )
}

pub(crate) fn resolve_packages(
    ctx: &Context<'_>,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    let serial = serial_of(input);
    let query = input
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ran = ctx
        .shell(
            serial,
            &["pm", "list", "packages", "-f"],
            Context::limits(PACKAGE_LIST_TIMEOUT_MS, PACKAGE_LIST_MAX_OUTPUT_BYTES),
        )
        .map_err(|error| ctx.retain_child(error))?;
    let (packages, unparsed) = parse_package_list_output(&ran.stdout);
    let needle = query.to_lowercase();
    let matches: Vec<&crate::adb::device_output::AdbPackageEntry> = packages
        .iter()
        .filter(|entry| entry.package_name.to_lowercase().contains(&needle))
        .collect();
    let exact_match = matches.len() == 1 && matches[0].package_name.to_lowercase() == needle;
    let matches_json: Vec<Value> = matches
        .iter()
        .map(|entry| {
            json!({
                "package_name": entry.package_name,
                "base_apk_device_path": entry.base_apk_device_path,
            })
        })
        .collect();
    let coverage = if unparsed.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let result = json!({
        "client": ctx.client,
        "serial": serial,
        "query": query,
        "matches": matches_json,
        "exact_match": exact_match,
        "coverage": coverage,
    });
    let mut limitations = vec![
        "Matching is a case-insensitive substring over package names; application display labels are not part of pm output".to_owned(),
    ];
    limitations.extend(provider::unparsed_overflow_limitation(&unparsed));
    finish(ctx, parameters(input), result, limitations, None)
}
