//! CLI-owned readiness projection for `rea doctor`.
//!
//! Provider adapters own configuration and availability checks. This module
//! only reads composed binary-session candidate status and projects it into
//! the public doctor report; it never starts a provider process.

use crate::analysis::outcome;
use crate::invoke::Runner;
use rea_application::maintenance_client_config::{
    ClientConfigFormat, RegistrationInspection, RegistrationState, dialect_for_client,
    inspect_path_with_dialect_and_identity,
};
use rea_application::maintenance_clients::{
    ClientConfigurationFormat, ClientPlatform, ClientResolutionContext, supported_client_targets,
};
use rea_application::maintenance_skills::{inspect_skill, read_bundle, skill_destinations};
use rea_tools_binary::inspect_target;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::Path;

/// Run the read-only doctor workflow for the parsed CLI options.
pub fn run(options: &Value, runner: &Runner<'_>) -> Value {
    let requested_providers = string_array(options, "provider");
    let requested_clients = string_array(options, "client");
    let require_skill = options
        .get("skill")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let target = options
        .get("target")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let audit_wide = requested_providers.is_empty()
        && requested_clients.is_empty()
        && !require_skill
        && target.is_none();
    let client_context = client_context(runner);
    let (candidates, discovery_error, server_identity) = candidate_status(runner);
    let all_provider_ids = candidates
        .iter()
        .filter_map(|candidate| candidate["provider"]["id"].as_str())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let provider_ids = requested_providers.clone();
    let selected_provider_ids = if audit_wide {
        all_provider_ids.clone()
    } else {
        provider_ids.clone()
    };

    let selected_provider_checks = selected_provider_ids
        .iter()
        .map(|provider_id| provider_check(provider_id, &candidates, discovery_error.as_ref()))
        .collect::<Vec<_>>();
    let provider_inspection_value = provider_inspections(&candidates, runner);
    let supplemental_provider_checks =
        supplemental_provider_checks(&provider_inspection_value, &all_provider_ids);
    let informational_provider_checks = if audit_wide {
        Vec::new()
    } else {
        all_provider_ids
            .iter()
            .filter(|provider_id| !provider_ids.iter().any(|selected| selected == *provider_id))
            .map(|provider_id| provider_check(provider_id, &candidates, discovery_error.as_ref()))
            .collect::<Vec<_>>()
    };
    let mut selected_checks = selected_provider_checks.clone();
    let mut checks = selected_provider_checks;
    let mut skill_identity_check = None;
    let node_check = native_node_check();
    let host_check = native_host_check();
    let identity_check = package_identity_check();
    selected_checks.push(node_check.clone());
    checks.push(node_check);
    checks.push(host_check);
    checks.push(identity_check);
    checks.extend(external_tool_checks(runner));
    selected_checks.extend(
        supplemental_provider_checks
            .iter()
            .filter(|check| {
                requested_providers
                    .iter()
                    .any(|provider| check_matches_provider(check, provider))
            })
            .cloned(),
    );
    checks.extend(supplemental_provider_checks);
    checks.extend(informational_provider_checks);
    if let Some(error) = discovery_error.as_ref() {
        checks.push(discovery_check(error));
    }
    if let Some(path) = target.as_deref() {
        let check = target_check(path, &runner.cancellation);
        selected_checks.push(check.clone());
        checks.push(check);
    }
    if let Ok(context) = client_context.as_ref() {
        let check = skill_check(context, &requested_clients);
        if require_skill {
            selected_checks.push(check.clone());
        }
        skill_identity_check = Some(check.clone());
        checks.push(check);
    }
    if let Err(error) = client_context.as_ref() {
        let check = environment_check(error);
        if audit_wide || !requested_clients.is_empty() || require_skill {
            selected_checks.push(check.clone());
        }
        checks.push(check);
    }
    let client_checks = client_context
        .as_ref()
        .map(|context| client_checks(context, &requested_clients))
        .unwrap_or_default();
    selected_checks.extend(client_checks.iter().filter_map(|check| {
        requested_clients
            .iter()
            .any(|client| check["name"].as_str() == Some(format!("registration:{client}").as_str()))
            .then_some(check.clone())
    }));
    checks.extend(client_checks);
    if let Some(reason) = runner.cancellation.reason() {
        let check = cancellation_check(reason);
        selected_checks.push(check.clone());
        checks.push(check);
    }
    let environment_healthy = checks.iter().all(|check| {
        check["ok"] == Value::Bool(true)
            || optional_unconfigured_check(check, &provider_inspection_value, runner)
    });
    let healthy = if audit_wide {
        environment_healthy
    } else {
        selected_checks
            .iter()
            .all(|check| check["ok"] == Value::Bool(true))
    };
    let scope_checks = if audit_wide {
        checks.clone()
    } else {
        selected_checks
    };
    let informational_checks = checks
        .iter()
        .filter(|check| !scope_checks.iter().any(|selected| selected == *check))
        .cloned()
        .collect::<Vec<_>>();

    json!({
        "healthy": healthy,
        "environment_healthy": environment_healthy,
        "scope": {
            "mode": if audit_wide { "audit-wide" } else { "explicit" },
            "clients": requested_clients,
            "providers": provider_ids,
            "skill": require_skill,
            "target": target,
        },
        "scope_checks": scope_checks,
        "informational_checks": informational_checks,
        "providerInspections": provider_inspection_value,
        "checks": checks,
        "identity": package_identity_report(
            server_identity.as_ref(),
            skill_identity_check.as_ref(),
        ),
    })
}

fn optional_unconfigured_check(check: &Value, inspections: &Value, runner: &Runner<'_>) -> bool {
    let Some(name) = check["name"].as_str() else {
        return false;
    };
    if let Some(inspection) = inspections
        .as_array()
        .into_iter()
        .flatten()
        .find(|inspection| {
            inspection["id"]
                .as_str()
                .is_some_and(|id| name == id || name.starts_with(&format!("{id}-")))
        })
    {
        return inspection["configured"] == Value::Bool(false);
    }
    let variable = match name {
        "jadx" | "jadx-configuration" => "REA_JADX_MCP_JAR",
        "kuna-installation" | "kuna" => "REA_KUNA_COMMAND",
        "hopper" => "HOPPER_LAUNCHER_PATH",
        _ => return false,
    };
    runner
        .session
        .environment()
        .get(variable)
        .is_none_or(|value| value.is_empty())
}

fn check_matches_provider(check: &Value, provider_id: &str) -> bool {
    check["name"]
        .as_str()
        .is_some_and(|name| name == provider_id || name.starts_with(&format!("{provider_id}-")))
}

fn supplemental_provider_checks(inspections: &Value, runtime_ids: &[String]) -> Vec<Value> {
    inspections
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|inspection| {
            let provider_id = inspection["id"].as_str()?;
            if runtime_ids.iter().any(|id| id == provider_id) {
                return None;
            }
            let checks = inspection["checks"].as_array()?;
            Some(
                checks
                    .iter()
                    .map(|check| {
                        let name = check["name"].as_str().unwrap_or("check");
                        json!({
                            "name": if name == "configuration" {
                                provider_id.to_owned()
                            } else if name == "registration" {
                                format!("{provider_id}-registration")
                            } else {
                                format!("{provider_id}-{name}")
                            },
                            "ok": check["ok"],
                            "code": check["code"],
                            "classification": if check["ok"] == Value::Bool(true) { "healthy" } else { check["classification"].as_str().unwrap_or("unknown") },
                            "detail": check["detail"],
                            "remediation": check["remediation"],
                            "details": check["details"],
                        })
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .collect()
}

fn native_node_check() -> Value {
    json!({
        "name": "node",
        "ok": true,
        "classification": "healthy",
        "detail": "Native Rust CLI runtime; Node.js compatibility is not applicable.",
        "details": {"runtime": "native-rust"},
    })
}

fn native_host_check() -> Value {
    let platform = std::env::consts::OS;
    let architecture = std::env::consts::ARCH;
    let supported = matches!(platform, "macos" | "linux" | "windows")
        && matches!(architecture, "x86_64" | "aarch64");
    json!({
        "name": "host",
        "ok": supported,
        "classification": if supported { "healthy" } else { "unsupported_host" },
        "detail": format!("{platform} {architecture}"),
        "remediation": if supported { Value::Null } else { Value::String("Run REA on macOS, Linux, or Windows x64/ARM64.".to_owned()) },
        "details": {"platform": platform, "architecture": architecture},
    })
}

fn external_tool_checks(runner: &Runner<'_>) -> Vec<Value> {
    vec![
        configured_tool_check(
            "jadx",
            "REA_JADX_MCP_JAR",
            "Set REA_JADX_MCP_JAR to the absolute path of a caller-supplied jadx-headless-mcp JAR.",
            runner,
        ),
        configured_tool_check(
            "kuna-installation",
            "REA_KUNA_COMMAND",
            "Set REA_KUNA_COMMAND to the absolute path of a caller-supplied kuna executable.",
            runner,
        ),
        configured_tool_check(
            "hopper",
            "HOPPER_LAUNCHER_PATH",
            "Set HOPPER_LAUNCHER_PATH to a caller-supplied Hopper launcher to inspect its configuration.",
            runner,
        ),
    ]
}

fn configured_tool_check(
    name: &str,
    variable: &str,
    remediation: &str,
    runner: &Runner<'_>,
) -> Value {
    let configured = runner
        .session
        .environment()
        .get(variable)
        .filter(|value| !value.is_empty());
    let Some(path) = configured else {
        return json!({
            "name": name,
            "ok": false,
            "classification": "missing_analysis_engine",
            "detail": remediation,
            "details": {"configured": false},
            "remediation": remediation,
        });
    };
    let readable = std::fs::metadata(path).is_ok();
    json!({
        "name": name,
        "ok": readable,
        "classification": if readable { "healthy" } else { "missing_analysis_engine" },
        "detail": path,
        "details": {"configured": true, "path": path},
        "remediation": if readable { Value::Null } else { Value::String(format!("Verify that {variable} points to a readable caller-supplied executable or JAR.")) },
    })
}

fn package_identity_check() -> Value {
    match rea_application::package_identity::discover_current_package_root() {
        Ok(identity) => json!({
            "name": "identity",
            "ok": true,
            "classification": "healthy",
            "detail": identity.package_root.display().to_string(),
            "details": {
                "package_root": identity.package_root,
                "manifest": identity.manifest_path,
                "launcher": identity.launcher_path,
                "native_bin": identity.native_bin_path,
                "version": identity.version,
                "installation_kind": match identity.installation_kind {
                    rea_application::package_identity::PackageInstallationKind::NodePackage => "node-package",
                    rea_application::package_identity::PackageInstallationKind::StandaloneRelease => "standalone-release",
                },
                "target": identity.target,
            },
        }),
        Err(error) => json!({
            "name": "identity",
            "ok": false,
            "code": "package_identity_unavailable",
            "classification": "unknown",
            "detail": error.to_string(),
            "remediation": "Run doctor from an owned REA installation.",
        }),
    }
}

fn package_identity_report(server_identity: Option<&Value>, skill_check: Option<&Value>) -> Value {
    if let Some(identity) = server_identity {
        return json!({
            "cli_package_version": identity["package"]["version"],
            "expected_skill_version": identity["skill"]["expected_version"],
            "sdk": identity["sdk"],
            "sdk_source": "frozen_catalog_metadata",
            "runtime_sdk": {
                "implementation": "native-rust",
                "rmcp": "3.6.0",
                "server_version": rea_mcp::catalog::catalog().server_version,
            },
            "catalog": identity["catalog"],
            "live_server": {
                "state": "unknown",
                "observation": "local_binary_session_identity",
                "remediation": "Inspect the external MCP client/server process to compare live registration identity.",
            },
            "installations": {"paths": [], "state": "unknown"},
            "skill": skill_identity_details(skill_check),
            "registrations": [],
        });
    }
    match rea_application::package_identity::discover_current_package_root() {
        Ok(identity) => json!({
            "cli_package_version": identity.version,
            "expected_skill_version": Value::Null,
            "sdk": Value::Null,
            "sdk_source": "unavailable",
            "runtime_sdk": {
                "implementation": "native-rust",
                "rmcp": "3.6.0",
                "server_version": rea_mcp::catalog::catalog().server_version,
            },
            "catalog": Value::Null,
            "live_server": {"state": "unknown", "remediation": "Call binary_session in the active client to inspect the running server identity."},
            "installations": {"paths": [identity.package_root], "state": "single", "kind": match identity.installation_kind {
                rea_application::package_identity::PackageInstallationKind::NodePackage => "node-package",
                rea_application::package_identity::PackageInstallationKind::StandaloneRelease => "standalone-release",
            }},
            "skill": {"installed_version": Value::Null, "installed_tool_count": Value::Null, "state": "unknown", "remediation": Value::Null},
            "registrations": [],
        }),
        Err(error) => json!({
            "cli_package_version": Value::Null,
            "expected_skill_version": Value::Null,
            "sdk": Value::Null,
            "sdk_source": "unavailable",
            "runtime_sdk": {
                "implementation": "native-rust",
                "rmcp": "3.6.0",
                "server_version": rea_mcp::catalog::catalog().server_version,
            },
            "catalog": Value::Null,
            "live_server": {"state": "unknown", "remediation": "Call binary_session in the active client to inspect the running server identity."},
            "installations": {"paths": [], "state": "unknown"},
            "skill": {"installed_version": Value::Null, "installed_tool_count": Value::Null, "state": "unknown", "remediation": error.to_string()},
            "registrations": [],
        }),
    }
}

fn skill_identity_details(check: Option<&Value>) -> Value {
    let Some(check) = check else {
        return json!({
            "installed_version": Value::Null,
            "installed_tool_count": Value::Null,
            "state": "unknown",
            "remediation": "Run rea doctor with a readable bundled skill installation.",
        });
    };
    let aligned = check["ok"] == Value::Bool(true);
    let destinations = check["details"]["destinations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let has_installed_destination = destinations
        .iter()
        .any(|destination| destination["identity"]["installed"] == Value::Bool(true));
    let installed_versions = destinations
        .iter()
        .filter_map(|destination| destination["identity"]["version"].as_str())
        .collect::<Vec<_>>();
    let tool_counts = destinations
        .iter()
        .filter_map(|destination| destination["identity"]["tool_count"].as_u64())
        .collect::<Vec<_>>();
    json!({
        "installed_version": uniform_string(&installed_versions),
        "installed_tool_count": uniform_u64(&tool_counts),
        "state": if aligned { "aligned" } else if has_installed_destination { "stale" } else { "missing" },
        "destinations": destinations,
        "remediation": check.get("remediation").cloned().unwrap_or(Value::Null),
    })
}

fn uniform_string(values: &[&str]) -> Value {
    values
        .first()
        .filter(|_| values.iter().all(|value| *value == values[0]))
        .map(|value| Value::String((*value).to_owned()))
        .unwrap_or(Value::Null)
}

fn uniform_u64(values: &[u64]) -> Value {
    values
        .first()
        .filter(|_| values.iter().all(|value| *value == values[0]))
        .map(|value| Value::Number((*value).into()))
        .unwrap_or(Value::Null)
}

fn string_array(options: &Value, key: &str) -> Vec<String> {
    match options.get(key) {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn candidate_status(runner: &Runner<'_>) -> (Vec<Value>, Option<Value>, Option<Value>) {
    match outcome(runner.invoke("binary_session", json!({}))) {
        Ok(status) => {
            let candidates = status
                .get("analysis_provider_candidates")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let server_identity = status.get("server_identity").cloned();
            (candidates, None, server_identity)
        }
        Err(error) => (Vec::new(), Some(error), None),
    }
}

fn provider_check(
    provider_id: &str,
    candidates: &[Value],
    discovery_error: Option<&Value>,
) -> Value {
    let availability = candidates
        .iter()
        .find(|candidate| candidate["provider"]["id"].as_str() == Some(provider_id))
        .and_then(|candidate| candidate.get("availability"));
    let status = availability
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let available = status == "available";
    let detail = availability
        .map(|value| availability_detail(Some(value), status))
        .or_else(|| discovery_error.map(discovery_error_detail))
        .unwrap_or_else(|| availability_detail(None, status));
    let details = availability
        .and_then(|value| value.get("diagnostics"))
        .cloned()
        .or_else(|| discovery_error.cloned())
        .unwrap_or_else(|| json!({}));
    json!({
        "name": format!("{provider_id}-availability"),
        "ok": available,
        "code": availability
            .and_then(|value| value.get("code"))
            .cloned()
            .unwrap_or(Value::Null),
        "classification": availability_classification(status),
        "detail": detail,
        "remediation": if available { Value::Null } else { Value::String(format!("Configure the {provider_id} provider, then rerun rea doctor.")) },
        "details": details,
    })
}

fn provider_inspections(candidates: &[Value], runner: &Runner<'_>) -> Value {
    let mut inspections = candidates
        .iter()
        .filter_map(|candidate| runtime_provider_inspection(candidate, runner))
        .collect::<Vec<_>>();

    for provider_id in ["ghidra-rust", "ida", "jadx", "kuna"] {
        if !inspections
            .iter()
            .any(|inspection| inspection["id"].as_str() == Some(provider_id))
        {
            inspections.push(unverified_provider_inspection(provider_id, runner));
        }
    }

    Value::Array(inspections)
}

fn runtime_provider_inspection(candidate: &Value, runner: &Runner<'_>) -> Option<Value> {
    let provider = candidate.get("provider")?.as_object()?;
    let id = provider.get("id")?.as_str()?;
    let availability = candidate.get("availability")?;
    let status = availability["status"].as_str().unwrap_or("unknown");
    let available = status == "available";
    let detail = availability_detail(Some(availability), status);
    Some(json!({
        "id": id,
        "configured": configured_value(candidate),
        "available": available,
        // The candidate version is a native protocol/runtime value, not the
        // provider release version promised by the public doctor contract.
        "providerVersion": Value::Null,
        "registrationEnvironment": registration_environment(candidate, id, runner),
        "checks": [{
            "name": "availability",
            "ok": available,
            "code": availability["code"],
            "detail": detail,
            "remediation": if available { Value::Null } else { Value::String(format!("Configure the {id} provider, then rerun rea doctor.")) },
            "classification": availability_classification(status),
            "details": availability["diagnostics"],
        }],
    }))
}

fn unverified_provider_inspection(provider_id: &str, runner: &Runner<'_>) -> Value {
    let (configured, registration_environment, detail) = match provider_id {
        "ghidra-rust" => configured_registration(runner, "REA_GHIDRA_RUST_WORKER"),
        "ida" => configured_registration(runner, "REA_IDA_MCP_CONFIG"),
        "jadx" => configured_registration(runner, "REA_JADX_MCP_JAR"),
        "kuna" => configured_registration(runner, "REA_KUNA_COMMAND"),
        _ => (false, json!({}), "Unknown provider.".to_owned()),
    };
    json!({
        "id": provider_id,
        "configured": configured,
        "available": false,
        "providerVersion": Value::Null,
        "registrationEnvironment": registration_environment,
        "checks": [{
            "name": "registration",
            "ok": configured,
            "code": if configured { Value::String("runtime_unverified".to_owned()) } else { Value::String("not_configured".to_owned()) },
            "detail": detail,
            "remediation": if configured { Value::String(format!("The native runtime retained the {provider_id} registration, but did not claim live provider availability.")) } else { Value::String(format!("Configure the {provider_id} provider, then rerun rea doctor.")) },
            "classification": if configured { "unknown" } else { "missing_analysis_engine" },
            "details": {"availability": "unverified", "configured": configured},
        }],
    })
}

fn configured_registration(runner: &Runner<'_>, variable: &str) -> (bool, Value, String) {
    let value = runner
        .session
        .environment()
        .get(variable)
        .filter(|value| !value.is_empty());
    match value {
        Some(path) => {
            if !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
                return (
                    true,
                    json!({}),
                    format!("{variable} is configured, but the selected path is not readable."),
                );
            }
            let mut environment = Map::new();
            environment.insert(variable.to_owned(), Value::String(path.clone()));
            (
                true,
                Value::Object(environment),
                format!(
                    "{variable} is configured; the native runtime did not perform a live provider probe."
                ),
            )
        }
        None => (false, json!({}), format!("{variable} is not configured.")),
    }
}

fn availability_detail(availability: Option<&Value>, status: &str) -> String {
    if let Some(reason) = availability
        .and_then(|value| value.get("reason"))
        .and_then(Value::as_str)
    {
        return reason.to_owned();
    }

    match status {
        "available" => "The provider is configured and available.".to_owned(),
        "unavailable" => "The provider is unavailable.".to_owned(),
        _ => "The provider availability could not be determined.".to_owned(),
    }
}

fn availability_classification(status: &str) -> &'static str {
    match status {
        "available" => "healthy",
        "unavailable" => "missing_analysis_engine",
        _ => "unknown",
    }
}

fn discovery_error_detail(error: &Value) -> String {
    error
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| error.get("detail").and_then(Value::as_str))
        .unwrap_or("Provider availability discovery failed.")
        .to_owned()
}

fn target_check(path: &str, cancellation: &rea_core::cancellation::Cancellation) -> Value {
    match inspect_target(path, cancellation) {
        Ok(_) => json!({
            "name": "target",
            "ok": true,
            "code": Value::Null,
            "classification": "healthy",
            "detail": path,
        }),
        Err(error) => {
            let detail = error.to_string();
            let projection = error.project();
            json!({
                "name": "target",
                "ok": false,
                "code": projection.get("code").cloned().unwrap_or(Value::Null),
                "classification": target_classification(&projection),
                "detail": detail,
                "remediation": projection
                    .get("remediation")
                    .cloned()
                    .unwrap_or_else(|| json!("Supply a readable local app or program path.")),
                "details": projection,
            })
        }
    }
}

fn discovery_check(error: &Value) -> Value {
    json!({
        "name": "provider-discovery",
        "ok": false,
        "code": error.get("code").cloned().unwrap_or(Value::Null),
        "classification": "runtime_failure",
        "detail": discovery_error_detail(error),
        "remediation": "Resolve provider discovery errors, then rerun rea doctor.",
        "details": error,
    })
}

fn cancellation_check(reason: &str) -> Value {
    json!({
        "name": "doctor-cancellation",
        "ok": false,
        "code": "cancelled",
        "classification": "cancelled",
        "detail": reason,
        "remediation": Value::Null,
    })
}

fn target_classification(projection: &Value) -> &'static str {
    match projection.get("category").and_then(Value::as_str) {
        Some("unsupported_target") => "unsupported_target",
        Some("cancelled") => "cancelled",
        Some("invalid_input") => "invalid_input",
        Some("execution_failure") => "runtime_failure",
        Some("unavailable") => "unavailable",
        Some("access_denied") => "access_denied",
        Some(_) => "unknown",
        None => "unknown",
    }
}

fn configured_value(candidate: &Value) -> Value {
    candidate
        .get("configured")
        .and_then(Value::as_bool)
        .map(Value::Bool)
        .or_else(|| {
            candidate["availability"]["diagnostics"]["configured"]
                .as_bool()
                .map(Value::Bool)
        })
        .or_else(|| {
            candidate["availability"]["diagnostics"]["configured_provider"]
                .as_bool()
                .map(Value::Bool)
        })
        .unwrap_or(Value::Null)
}

fn registration_environment(candidate: &Value, provider_id: &str, runner: &Runner<'_>) -> Value {
    if provider_id == "ghidra-rust"
        && candidate["availability"]["status"].as_str() == Some("available")
    {
        let environment = runner.session.environment();
        let mut values = Map::new();
        for key in ["REA_GHIDRA_RUST_WORKER", "REA_GHIDRA_RUST_CACHE_DIR"] {
            if let Some(value) = environment.get(key).filter(|value| !value.is_empty()) {
                values.insert(key.to_owned(), Value::String(value.clone()));
            }
        }
        if !values.is_empty() {
            return Value::Object(values);
        }
    }

    candidate
        .get("registrationEnvironment")
        .cloned()
        .or_else(|| {
            candidate["availability"]["diagnostics"]
                .get("registrationEnvironment")
                .cloned()
        })
        .or_else(|| {
            candidate["availability"]["diagnostics"]
                .get("registration_environment")
                .cloned()
        })
        .unwrap_or_else(|| json!({}))
}

fn client_context(runner: &Runner<'_>) -> Result<ClientResolutionContext, String> {
    let session_environment = runner.session.environment();
    let platform = match std::env::consts::OS {
        "macos" => ClientPlatform::Macos,
        "windows" => ClientPlatform::Windows,
        _ => ClientPlatform::Linux,
    };
    let home_name = if platform == ClientPlatform::Windows {
        "USERPROFILE"
    } else {
        "HOME"
    };
    let home = session_environment
        .get(home_name)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            (home_name != "HOME")
                .then(|| session_environment.get("HOME"))
                .flatten()
                .filter(|value| !value.is_empty())
        })
        .map(std::path::PathBuf::from)
        .ok_or_else(|| format!("session environment is missing {home_name}"))?;
    let cwd = std::env::current_dir()
        .map_err(|error| format!("could not determine the current directory: {error}"))?;
    let environment = session_environment
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();

    Ok(ClientResolutionContext::new(
        home,
        cwd,
        platform,
        environment,
    ))
}

fn environment_check(error: &str) -> Value {
    json!({
        "name": "client-environment",
        "ok": false,
        "code": "environment_unavailable",
        "classification": "unknown",
        "detail": error,
        "remediation": "Start a new REA session with a complete home-directory environment, then rerun rea doctor.",
    })
}

fn client_checks(context: &ClientResolutionContext, requested: &[String]) -> Vec<Value> {
    let targets = supported_client_targets(context);
    let current_entrypoint = verified_current_entrypoint();
    let known_ids = targets
        .iter()
        .map(|target| target.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let selected = if requested.is_empty() {
        targets
            .into_iter()
            .filter(|target| target.evidence_paths.iter().any(|path| path.exists()))
            .collect::<Vec<_>>()
    } else {
        targets
            .into_iter()
            .filter(|target| requested.iter().any(|id| id == &target.id))
            .collect::<Vec<_>>()
    };

    let mut checks = selected
        .iter()
        .map(|target| {
            let format = client_config_format(target.format);
            let server_path = target.server_key.split('.').collect::<Vec<_>>();
            let dialect = dialect_for_client(&target.id);
            registration_check(
                &target.id,
                &inspect_path_with_dialect_and_identity(
                    &target.path,
                    format,
                    &server_path,
                    dialect,
                    None,
                    current_entrypoint.as_deref(),
                ),
            )
        })
        .collect::<Vec<_>>();
    if !requested.is_empty() {
        checks.extend(
            requested
                .iter()
                .filter(|client| !known_ids.contains(*client))
                .map(|client| {
                    json!({
                        "name": format!("registration:{client}"),
                        "ok": false,
                        "code": "unsupported_client",
                        "classification": "config_drift",
                        "detail": format!("Requested client {client} was not detected."),
                        "remediation": format!("Install or select {client}, then run rea setup --client {client}."),
                    })
                }),
        );
    }
    checks
}

fn verified_current_entrypoint() -> Option<std::path::PathBuf> {
    let executable = std::env::current_exe().ok()?;
    rea_application::package_identity::discover_package_root(&executable)
        .ok()
        .map(|_| executable)
}

fn client_config_format(format: ClientConfigurationFormat) -> ClientConfigFormat {
    match format {
        ClientConfigurationFormat::Json => ClientConfigFormat::Json,
        ClientConfigurationFormat::Jsonc => ClientConfigFormat::Jsonc,
        ClientConfigurationFormat::Toml => ClientConfigFormat::Toml,
        ClientConfigurationFormat::Yaml => ClientConfigFormat::Yaml,
        ClientConfigurationFormat::Unsupported => ClientConfigFormat::Json,
    }
}

fn registration_check(client: &str, inspection: &RegistrationInspection) -> Value {
    let name = format!("registration:{client}");
    let path = inspection.path.display().to_string();
    match &inspection.state {
        RegistrationState::Owned => json!({
            "name": name,
            "ok": true,
            "code": Value::Null,
            "classification": "healthy",
            "detail": path,
            "remediation": Value::Null,
        }),
        RegistrationState::Missing | RegistrationState::Absent => json!({
            "name": name,
            "ok": false,
            "code": "missing_registration",
            "classification": "config_drift",
            "detail": path,
            "remediation": format!("Run rea setup --client {client}."),
        }),
        RegistrationState::Foreign => json!({
            "name": name,
            "ok": false,
            "code": "foreign_registration",
            "classification": "config_drift",
            "detail": path,
            "remediation": "Review the existing registration before changing it.",
        }),
        RegistrationState::Malformed(detail) => json!({
            "name": name,
            "ok": false,
            "code": "malformed_registration",
            "classification": "config_drift",
            "detail": detail,
            "remediation": format!("Repair the configuration at {path}, then rerun rea doctor."),
        }),
        RegistrationState::Unreadable(detail) => json!({
            "name": name,
            "ok": false,
            "code": "unreadable_registration",
            "classification": "unknown",
            "detail": detail,
            "remediation": format!("Restore read access to {path}, then rerun rea doctor."),
        }),
    }
}

fn skill_check(context: &ClientResolutionContext, requested_clients: &[String]) -> Value {
    let destinations = match skill_destinations(
        context,
        (!requested_clients.is_empty()).then_some(requested_clients),
    ) {
        Ok(destinations) => destinations,
        Err(error) => {
            return json!({
                "name": "skill:identity",
                "ok": false,
                "code": "invalid_skill_destination",
                "classification": "config_drift",
                "detail": error.to_string(),
                "remediation": "Select a supported skill destination, then rerun rea doctor.",
            });
        }
    };
    let bundle_root = match rea_application::package_identity::discover_current_package_root() {
        Ok(identity) => identity
            .package_root
            .join("skills/reverse-engineer-anything"),
        Err(error) => {
            return json!({
                "name": "skill:identity",
                "ok": false,
                "code": "package_identity_unavailable",
                "classification": "runtime_failure",
                "detail": error.to_string(),
                "remediation": "Run doctor from an owned REA installation.",
            });
        }
    };
    let bundle = match read_bundle(Path::new(&bundle_root)) {
        Ok(bundle) => bundle,
        Err(error) => {
            return json!({
                "name": "skill:identity",
                "ok": false,
                "code": "skill_bundle_unreadable",
                "classification": "runtime_failure",
                "detail": error.to_string(),
                "remediation": "Restore the bundled skill files, then rerun rea doctor.",
            });
        }
    };
    let identities = destinations
        .iter()
        .map(|destination| {
            json!({
                "client": destination.client,
                "path": destination.path,
                "identity": inspect_skill(&destination.path, &bundle),
            })
        })
        .collect::<Vec<_>>();
    let aligned = identities.iter().all(|entry| {
        entry["identity"]["installed"] == Value::Bool(true)
            && entry["identity"]["canonical"] == Value::Bool(true)
            && entry["identity"]["issues"]
                .as_array()
                .is_some_and(|issues| issues.is_empty())
    }) && !identities.is_empty();
    json!({
        "name": "skill:identity",
        "ok": aligned,
        "code": if aligned { Value::Null } else { Value::String("skill_identity_drift".into()) },
        "classification": if aligned { "healthy" } else { "config_drift" },
        "detail": if aligned { "Installed REA skill identity is aligned." } else { "Installed REA skill identity is missing or stale." },
        "remediation": if aligned { Value::Null } else { Value::String("Run rea setup to update the installed REA skill.".into()) },
        "details": {"destinations": identities},
    })
}
