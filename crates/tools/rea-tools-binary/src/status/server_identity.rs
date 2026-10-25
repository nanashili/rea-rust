//! `createServerIdentity` (`src/serverIdentity.ts`), with product/SDK identity
//! (`src/identity.ts`, `src/generatedPackageMetadata.ts`) and catalog identity
//! (`src/catalogIdentity.ts`).

use super::catalog_digests::{catalog_counts, catalog_digests};
use serde_json::{Value, json};
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Product / SDK identity (src/identity.ts, src/generatedPackageMetadata.ts).
// ---------------------------------------------------------------------------

/// `PACKAGE_METADATA.name`.
pub(crate) const PACKAGE_NAME: &str = "rea-agents";
/// `PACKAGE_METADATA.version`.
/// `PRODUCT_IDENTITY.packageVersion`.
pub const PACKAGE_VERSION: &str = "6.7.0";
/// `PRODUCT_IDENTITY.mcpServerKey`.
pub(crate) const MCP_SERVER_KEY: &str = "rea";
/// `PRODUCT_IDENTITY.skillName`.
pub(crate) const SKILL_NAME: &str = "reverse-engineer-anything";
/// `PACKAGE_METADATA.skillVersion`.
pub(crate) const SKILL_VERSION: &str = "42";
/// `SDK_IDENTITY` package versions (server, client_test, core).
pub(crate) const SDK_SERVER_VERSION: &str = "2.3.1";
pub(crate) const SDK_CLIENT_TEST_VERSION: &str = "2.3.1";
pub(crate) const SDK_CORE_VERSION: &str = "2.3.1";

// ---------------------------------------------------------------------------
// Input.
// ---------------------------------------------------------------------------

/// Inputs to `createServerIdentity`.
pub(crate) struct ServerIdentityInput<'a> {
    pub started_at: SystemTime,
    pub expected_package_version: Option<&'a str>,
    pub expected_catalog_digest: Option<&'a str>,
    pub expected_server_path: Option<&'a str>,
    /// Connected client `(name, version)`.
    pub client: Option<(String, String)>,
    pub protocol_version: Option<String>,
    /// `REA_BUILD_COMMIT` from the session environment.
    pub build_commit: Option<String>,
    pub compact_input_schemas: bool,
    pub include_output_schemas: bool,
}

// ---------------------------------------------------------------------------
// Date.toISOString() for SystemTime.
// ---------------------------------------------------------------------------

/// Format a `SystemTime` like JavaScript `Date.toISOString()`:
/// `YYYY-MM-DDTHH:MM:SS.mmmZ` in UTC with millisecond precision.
fn to_iso_string(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let total_millis = duration.as_millis();
    let millis = (total_millis % 1000) as u64;
    let total_secs = (total_millis / 1000) as i64;

    let secs_of_day = total_secs.rem_euclid(86_400);
    let days = total_secs.div_euclid(86_400);

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Convert a day count since 1970-01-01 to `(year, month, day)`.
/// Howard Hinnant's `civil_from_days` algorithm (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

// ---------------------------------------------------------------------------
// node:path resolve semantics.
// ---------------------------------------------------------------------------

/// `path.resolve(single)` of one path against the process working directory.
///
/// An absolute input is normalized and returned; a relative input is resolved
/// against the current working directory. Trailing slashes are stripped (the
/// root is preserved). This mirrors the host `node:path.resolve` used to
/// compare `expected_server_path` with the native executable path.
fn resolve_path(input: &str) -> String {
    let path = std::path::Path::new(input);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("/"))
            .join(path)
    };
    normalize_path(&joined)
}

/// Lexically normalize a path (resolve `.`/`..`, collapse separators) without
/// touching the filesystem, matching `node:path.resolve`'s normalization.
fn normalize_path(path: &std::path::Path) -> String {
    use std::path::Component;
    let mut normalized: Vec<std::ffi::OsString> = Vec::new();
    let mut prefix = std::path::PathBuf::new();
    let mut has_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix_component) => {
                prefix = std::path::PathBuf::from(prefix_component.as_os_str());
            }
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized
                    .last()
                    .is_some_and(|last| last != std::ffi::OsStr::new(".."))
                {
                    normalized.pop();
                } else if !has_root {
                    normalized.push(std::ffi::OsString::from(".."));
                }
            }
            Component::Normal(part) => normalized.push(part.to_os_string()),
        }
    }
    let mut result = prefix;
    if has_root {
        result.push(std::path::MAIN_SEPARATOR_STR);
    }
    for part in normalized {
        result.push(part);
    }
    result.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Package root and command path.
// ---------------------------------------------------------------------------

/// The native executable path, like TS `serverPath` (its entrypoint path).
///
/// TS reads the module entrypoint; the native runtime reads
/// `std::env::current_exe()`. An unavailable path is `None`.
fn command_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .map(|path| normalize_path(&path))
}

/// Package ownership is established by the shared manifest and launcher
/// inspector. An executable outside a verified package has an unknown root.
fn package_root() -> Option<String> {
    rea_application::package_identity::discover_current_package_root()
        .ok()
        .map(|identity| normalize_path(&identity.package_root))
}

// ---------------------------------------------------------------------------
// createServerIdentity.
// ---------------------------------------------------------------------------

/// `createServerIdentity`: build one runtime identity object, preserving the
/// exact key order and alignment semantics of the TS projection.
pub(crate) fn server_identity(input: &ServerIdentityInput<'_>) -> Value {
    let started_at = to_iso_string(input.started_at);
    let command = command_path();
    // TS `serverPath = input.commandPath || undefined` — an empty path is None.
    let server_path = command.as_deref().filter(|path| !path.is_empty());

    let digests = catalog_digests(input.compact_input_schemas, input.include_output_schemas);
    let combined_digest = digests.combined_sha256.clone();

    let mut reasons: Vec<&str> = Vec::new();
    if let Some(expected) = input.expected_package_version
        && expected != PACKAGE_VERSION
    {
        reasons.push("package_version_mismatch");
    }
    if let Some(expected) = input.expected_catalog_digest
        && expected != combined_digest
    {
        reasons.push("catalog_digest_mismatch");
    }
    if let Some(expected) = input.expected_server_path
        && let Some(server_path) = server_path
        && resolve_path(expected) != server_path
    {
        reasons.push("registration_path_mismatch");
    }

    let observed_expectation = input.expected_package_version.is_some()
        || input.expected_catalog_digest.is_some()
        || input.expected_server_path.is_some();
    let path_comparable = input.expected_server_path.is_none() || server_path.is_some();

    let state = if !reasons.is_empty() {
        "mcp_server_restart_required"
    } else if observed_expectation && path_comparable {
        "aligned"
    } else {
        "unknown"
    };

    let remediation = if !reasons.is_empty() {
        Value::String(
            "Restart the registered MCP server/client, then compare identity again.".to_owned(),
        )
    } else if observed_expectation && path_comparable {
        Value::Null
    } else if input.expected_server_path.is_some() && server_path.is_none() {
        Value::String(
            "The server entrypoint path is unavailable, so registration identity cannot be compared."
                .to_owned(),
        )
    } else {
        Value::String(
            "Supply expected package, catalog, or registration identity to compare the live server."
                .to_owned(),
        )
    };

    let client = match &input.client {
        None => Value::Null,
        Some((name, version)) => json!({ "name": name, "version": version }),
    };

    json!({
        "package": {
            "name": PACKAGE_NAME,
            "version": PACKAGE_VERSION,
            "root_path": package_root(),
            "build_commit": input.build_commit.clone().map_or(Value::Null, Value::String),
        },
        "server": {
            "name": MCP_SERVER_KEY,
            "version": PACKAGE_VERSION,
            "started_at": started_at,
            "command_path": server_path.map_or(Value::Null, |path| Value::String(path.to_owned())),
        },
        "sdk": {
            "server": SDK_SERVER_VERSION,
            "client_test": SDK_CLIENT_TEST_VERSION,
            "core": SDK_CORE_VERSION,
        },
        "negotiated_protocol_version": input.protocol_version.clone().map_or(Value::Null, Value::String),
        "client": client,
        "skill": {
            "name": SKILL_NAME,
            "expected_version": SKILL_VERSION,
        },
        "catalog": {
            "counts": catalog_counts(),
            "digests": digests.to_json(),
        },
        "protocol_features": {
            "progress": true,
            "cancellation": true,
            "elicitation": false,
        },
        "alignment": {
            "state": state,
            "reasons": reasons,
            "remediation": remediation,
        },
    })
}
