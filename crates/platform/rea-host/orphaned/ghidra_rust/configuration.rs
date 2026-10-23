//! Pure configuration and availability facts for the optional Rust Ghidra worker.
//!
//! This module deliberately does not start a worker.  The caller supplies an
//! environment snapshot so configuration inspection remains deterministic and
//! does not accidentally persist or inherit unrelated process state.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::Value;

pub const MAX_TIMEOUT_MS: u64 = 2_147_483_647;
pub const MAX_MEMORY_MIB: u64 = 8_589_934_591;
pub const MAX_BATCH_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BATCH_SELECTORS: usize = 1_000_000;
pub const MAX_SELECTOR_BYTES: usize = 4_096;
pub const MAX_SELECTOR_UTF16_CODE_UNITS: usize = 4_096;

const MISSING_WORKER_REASON: &str =
    "The Rust worker is not bundled with the npm package. From an REA source checkout, run `npm run build:ghidra:rust-worker`, then set REA_GHIDRA_RUST_WORKER to the absolute `native/ghidra-rust-worker/target/release/rea-ghidra-rust-worker` path.";
const INVALID_CONFIGURATION_REASON: &str =
    "Configure absolute REA_GHIDRA_RUST_WORKER and REA_GHIDRA_RUST_CACHE_DIR paths, a positive REA_GHIDRA_RUST_TIMEOUT_MS value, and an optional positive REA_GHIDRA_RUST_MEMORY_MIB threshold.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustConfiguration {
    pub command: PathBuf,
    pub cache_directory: PathBuf,
    pub timeout: Duration,
    pub memory_mib: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustBatchInput {
    pub addresses: Vec<String>,
}

/// Validate the strict batch shape and admission budget used by the worker.
pub fn parse_batch_input(value: &Value) -> Result<GhidraRustBatchInput, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "batch_decompile input must be an object".to_owned())?;

    if object.keys().any(|key| key != "addresses") {
        return Err("batch_decompile input contains an unknown field".into());
    }

    let addresses = match object.get("addresses") {
        None => Vec::new(),
        Some(value) => parse_address_selectors(value)?,
    };

    Ok(GhidraRustBatchInput { addresses })
}

fn parse_address_selectors(value: &Value) -> Result<Vec<String>, String> {
    let selectors = value
        .as_array()
        .ok_or_else(|| "addresses must be an array".to_owned())?;

    if selectors.len() > MAX_BATCH_SELECTORS {
        return Err(format!(
            "batch selectors exceed the {MAX_BATCH_SELECTORS} selector limit"
        ));
    }

    let mut serialized_size = 2;
    let mut addresses = Vec::with_capacity(selectors.len());

    for selector in selectors {
        let text = selector
            .as_str()
            .ok_or_else(|| "every address selector must be a string".to_owned())?;

        if text.len() > MAX_SELECTOR_BYTES {
            return Err(format!(
                "address selectors must be at most {MAX_SELECTOR_BYTES} bytes"
            ));
        }

        if text.encode_utf16().count() > MAX_SELECTOR_UTF16_CODE_UNITS {
            return Err(format!(
                "address selectors must be at most {MAX_SELECTOR_UTF16_CODE_UNITS} UTF-16 code units"
            ));
        }

        let encoded_selector = serde_json::to_vec(text)
            .map_err(|cause| format!("cannot measure address selector: {cause}"))?;
        serialized_size = serialized_size.saturating_add(encoded_selector.len() + 1);
        if serialized_size > MAX_BATCH_INPUT_BYTES {
            return Err(format!(
                "batch selectors exceed the {MAX_BATCH_INPUT_BYTES}-byte input budget"
            ));
        }

        addresses.push(text.to_owned());
    }

    Ok(addresses)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityCode {
    NotConfigured,
    UnsupportedHost,
    ExecutableMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Availability {
    pub available: bool,
    pub code: Option<AvailabilityCode>,
    pub reason: Option<String>,
    pub diagnostics: BTreeMap<String, String>,
}

impl GhidraRustConfiguration {
    pub fn from_environment(
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let command = absolute_path(environment, "REA_GHIDRA_RUST_WORKER")?;
        let cache_directory = absolute_path(environment, "REA_GHIDRA_RUST_CACHE_DIR")?;
        let timeout_ms = positive_integer(
            environment,
            "REA_GHIDRA_RUST_TIMEOUT_MS",
            MAX_TIMEOUT_MS,
        )?;
        let memory_mib = optional_positive_integer(
            environment,
            "REA_GHIDRA_RUST_MEMORY_MIB",
            MAX_MEMORY_MIB,
        )?;

        Ok(Self {
            command,
            cache_directory,
            timeout: Duration::from_millis(timeout_ms),
            memory_mib,
        })
    }

    /// Pass only worker controls that REA owns to the child environment.
    pub fn worker_environment(
        &self,
        environment: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        let mut worker = environment.clone();
        worker.insert(
            "REA_GHIDRA_RUST_CACHE_DIR".into(),
            self.cache_directory.display().to_string(),
        );
        worker.insert(
            "REA_GHIDRA_RUST_TIMEOUT_MS".into(),
            self.timeout.as_millis().to_string(),
        );
        worker.remove("REA_GHIDRA_RUST_MEMORY_MIB");

        #[cfg(target_os = "macos")]
        worker.insert("MallocSpaceEfficient".into(), "1".into());

        worker
    }
}

pub fn inspect_environment(environment: &BTreeMap<String, String>) -> Availability {
    if environment.get("REA_ANALYSIS_PROVIDER").map(String::as_str)
        != Some("ghidra-rust")
    {
        return unavailable(
            AvailabilityCode::NotConfigured,
            "Select this local adapter explicitly with REA_ANALYSIS_PROVIDER=ghidra-rust.",
        );
    }
    if environment.get("REA_GHIDRA_RUST_ENABLED").map(String::as_str) != Some("true") {
        return unavailable(
            AvailabilityCode::NotConfigured,
            "This local prototype is disabled. Set REA_GHIDRA_RUST_ENABLED=true to opt in.",
        );
    }

    if environment
        .get("REA_GHIDRA_RUST_WORKER")
        .map_or(true, String::is_empty)
    {
        return unavailable(
            AvailabilityCode::NotConfigured,
            MISSING_WORKER_REASON,
        );
    }
    if !cfg!(target_os = "macos") && !cfg!(target_os = "linux") {
        return unavailable(
            AvailabilityCode::UnsupportedHost,
            "The Rust worker requires macOS or Linux.",
        );
    }

    let configuration = match GhidraRustConfiguration::from_environment(environment) {
        Ok(configuration) => configuration,
        Err(_) => return unavailable(
            AvailabilityCode::NotConfigured,
            INVALID_CONFIGURATION_REASON,
        ),
    };

    if let Err(reason) = executable_check(&configuration.command) {
        return unavailable(AvailabilityCode::ExecutableMissing, reason);
    }

    let mut diagnostics = BTreeMap::new();
    diagnostics.insert("command".into(), configuration.command.display().to_string());
    diagnostics.insert(
        "cache_directory".into(),
        configuration.cache_directory.display().to_string(),
    );
    diagnostics.insert(
        "timeout_ms".into(),
        configuration.timeout.as_millis().to_string(),
    );
    diagnostics.insert("explicitly_enabled".into(), "true".into());
    diagnostics.insert("memory_enforcement".into(), "unavailable".into());
    diagnostics.insert(
        "memory_supervision".into(),
        if configuration.memory_mib.is_some() {
            "sampled_worker_rss"
        } else {
            "disabled"
        }
        .into(),
    );
    diagnostics.insert(
        "memory_limit_mib".into(),
        configuration
            .memory_mib
            .map_or_else(|| "null".into(), |value| value.to_string()),
    );
    diagnostics.insert("memory_limit_scope".into(), "worker_process_only".into());
    diagnostics.insert("memory_sample_interval_ms".into(), "1000".into());
    diagnostics.insert("memory_sample_timeout_ms".into(), "1000".into());
    diagnostics.insert("memory_hard_limit".into(), "false".into());
    diagnostics.insert(
        "memory_monitor_state".into(),
        if configuration.memory_mib.is_some() {
            "not_probed"
        } else {
            "disabled"
        }
        .into(),
    );

    Availability {
        available: true,
        code: None,
        reason: None,
        diagnostics,
    }
}

fn unavailable(code: AvailabilityCode, reason: &str) -> Availability {
    let mut diagnostics = BTreeMap::new();
    diagnostics.insert("worker_started".into(), "false".into());
    diagnostics.insert(
        "opt_in_environment".into(),
        "REA_GHIDRA_RUST_ENABLED=true".into(),
    );
    diagnostics.insert("memory_enforcement".into(), "unavailable".into());
    Availability {
        available: false,
        code: Some(code),
        reason: Some(reason.into()),
        diagnostics,
    }
}

fn absolute_path(
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<PathBuf, String> {
    let value = environment
        .get(name)
        .ok_or_else(|| format!("{name} is required"))?;
    let path = Path::new(value);
    if value.is_empty() || !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(path.to_path_buf())
}

fn positive_integer(
    environment: &BTreeMap<String, String>,
    name: &str,
    maximum: u64,
) -> Result<u64, String> {
    let value = environment
        .get(name)
        .ok_or_else(|| format!("{name} is required"))?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{name} must contain only decimal digits"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{name} is too large"))?;
    if parsed == 0 || parsed > maximum {
        return Err(format!("{name} must be between 1 and {maximum}"));
    }
    Ok(parsed)
}

fn optional_positive_integer(
    environment: &BTreeMap<String, String>,
    name: &str,
    maximum: u64,
) -> Result<Option<u64>, String> {
    match environment.get(name) {
        Some(_) => positive_integer(environment, name, maximum).map(Some),
        None => Ok(None),
    }
}

fn executable_check(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|cause| format!("Cannot execute the Rust worker: {cause}"))?;
    if !metadata.is_file() {
        return Err("The configured worker is not a regular file.".into());
    }
    executable_permission_check(&metadata)
}

#[cfg(unix)]
fn executable_permission_check(metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o111 == 0 {
        return Err("The configured worker is not executable.".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn executable_permission_check(_metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}
