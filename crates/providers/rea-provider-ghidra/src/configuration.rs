//! Local worker configuration, resource policy and the worker environment.
//!
//! Compatibility owners: `src/ghidra-rust/GhidraRustConfiguration.ts` and
//! `GhidraRustMemoryPolicy.ts`.
//!
//! Native-runtime selection: Rust Ghidra is the only Ghidra engine of the
//! native runtime, so it is configured by default instead of requiring the
//! original explicit opt-in. Every original setting still overrides the
//! default, and `REA_GHIDRA_RUST_ENABLED` set to anything other than `true`
//! disables the provider explicitly:
//!
//! - `REA_GHIDRA_RUST_WORKER`: absolute worker path; default
//!   `rea-ghidra-rust-worker` beside the running `rea` executable.
//! - `REA_GHIDRA_RUST_CACHE_DIR`: absolute cache directory; default
//!   `$XDG_CACHE_HOME/rea/ghidra-rust`, else the platform user cache
//!   directory (`~/Library/Caches/rea/ghidra-rust` on macOS,
//!   `~/.cache/rea/ghidra-rust` on Linux).
//! - `REA_GHIDRA_RUST_TIMEOUT_MS`: operation deadline; default 600000.
//! - `REA_GHIDRA_RUST_MEMORY_MIB`: optional sampled worker-RSS threshold.
//! - `REA_GHIDRA_RUST_DECOMPILE_THREADS`: parallel decompiler Programs; default
//!   the available parallelism up to 8, reduced to fit a configured memory
//!   threshold.
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) const MEMORY_SAMPLE_INTERVAL_MS: u64 = 1_000;
pub(crate) const MEMORY_SAMPLE_TIMEOUT_MS: u64 = 1_000;
pub(crate) const MIB: u64 = 1_024 * 1_024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub(crate) const MAX_MEMORY_MIB: u64 = MAX_SAFE_INTEGER / MIB;
const MAX_TIMEOUT_MS: u64 = 2_147_483_647;
/// Default operation deadline when `REA_GHIDRA_RUST_TIMEOUT_MS` is unset.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 600_000;
/// Highest accepted decompile thread count (the worker's own bound).
const MAX_DECOMPILE_THREADS: u64 = 64;
/// Default ceiling: each thread owns a full decompiler Program.
const DEFAULT_MAX_DECOMPILE_THREADS: usize = 4;
/// Sampled peak worker RSS per decompiler Program on a 118 MB Mach-O target
/// (about 600 MiB); used to keep the default inside a memory threshold.
const PROGRAM_MEMORY_MIB: u64 = 768;
/// File name of the worker executable distributed beside `rea`.
pub(crate) const WORKER_EXECUTABLE: &str = "rea-ghidra-rust-worker";

const BUILD_GUIDANCE: &str = "For a release install, keep `rea-ghidra-rust-worker` beside the rea executable. For a source build, run `cargo build --locked --release` in ghidra-rust-worker, then place the worker beside rea or set REA_GHIDRA_RUST_WORKER to its absolute path.";

/// Where each effective setting came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sources {
    pub worker: &'static str,
    pub cache_directory: &'static str,
    pub timeout_ms: &'static str,
    pub decompile_threads: &'static str,
}

/// `GhidraRustConfiguration`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Configuration {
    pub command: String,
    pub cache_directory: String,
    pub timeout_ms: u64,
    pub memory_mib: Option<u64>,
    pub decompile_threads: usize,
    pub sources: Sources,
}

/// Configuration inspection without starting the engine.
#[derive(Clone, Debug)]
pub(crate) enum Inspection {
    Available {
        configuration: Configuration,
        diagnostics: Map<String, Value>,
    },
    Unavailable {
        code: &'static str,
        reason: String,
        diagnostics: Map<String, Value>,
    },
}

impl Inspection {
    pub(crate) fn reason(&self) -> Option<&str> {
        match self {
            Self::Available { .. } => None,
            Self::Unavailable { reason, .. } => Some(reason),
        }
    }
}

/// `ghidraRustMemoryPolicy`: the sampled threshold is not a kernel ceiling.
pub(crate) fn memory_policy(memory_mib: Option<u64>) -> Map<String, Value> {
    let mut policy = Map::new();
    policy.insert("memory_enforcement".into(), json!("unavailable"));
    policy.insert(
        "memory_supervision".into(),
        json!(if memory_mib.is_none() {
            "disabled"
        } else {
            "sampled_worker_rss"
        }),
    );
    policy.insert("memory_limit_mib".into(), json!(memory_mib));
    policy.insert("memory_limit_scope".into(), json!("worker_process_only"));
    policy.insert(
        "memory_sample_interval_ms".into(),
        json!(MEMORY_SAMPLE_INTERVAL_MS),
    );
    policy.insert(
        "memory_sample_timeout_ms".into(),
        json!(MEMORY_SAMPLE_TIMEOUT_MS),
    );
    policy.insert("memory_hard_limit".into(), json!(false));
    policy
}

fn unavailable(code: &'static str, reason: impl Into<String>) -> Inspection {
    let mut diagnostics = Map::new();
    diagnostics.insert("worker_started".into(), json!(false));
    diagnostics.insert("memory_enforcement".into(), json!("unavailable"));
    Inspection::Unavailable {
        code,
        reason: reason.into(),
        diagnostics,
    }
}

fn setting<'a>(environment: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    environment
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

/// `^\d+$` followed by `Number(...)` within `1..=maximum`.
fn positive_decimal(text: &str, maximum: u64) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let trimmed = text.trim_start_matches('0');
    if trimmed.len() > 20 {
        return None;
    }
    let value = trimmed.parse::<u128>().ok().unwrap_or(0);
    (value >= 1 && value <= u128::from(maximum)).then_some(value as u64)
}

fn absolute(text: &str) -> bool {
    Path::new(text).is_absolute()
}

/// Default user cache directory for the worker's saved analysis.
fn default_cache_directory(environment: &HashMap<String, String>) -> Option<String> {
    if let Some(xdg) = setting(environment, "XDG_CACHE_HOME").filter(|path| absolute(path)) {
        return Some(join(xdg, &["rea", "ghidra-rust"]));
    }
    let home = setting(environment, "HOME").filter(|path| absolute(path))?;
    if cfg!(target_os = "macos") {
        Some(join(home, &["Library", "Caches", "rea", "ghidra-rust"]))
    } else {
        Some(join(home, &[".cache", "rea", "ghidra-rust"]))
    }
}

fn join(base: &str, parts: &[&str]) -> String {
    let mut path = PathBuf::from(base);
    for part in parts {
        path.push(part);
    }
    path.to_string_lossy().into_owned()
}

/// The worker executable distributed beside the running `rea`.
fn default_worker(current_executable: Option<&Path>) -> Option<String> {
    let directory = current_executable?.parent()?;
    directory
        .join(WORKER_EXECUTABLE)
        .to_str()
        .map(str::to_owned)
}

/// `inspectGhidraRustConfiguration` with native-runtime defaults.
pub(crate) fn inspect(
    environment: &HashMap<String, String>,
    current_executable: Option<&Path>,
) -> Inspection {
    let enabled = environment
        .get("REA_GHIDRA_RUST_ENABLED")
        .map(String::as_str);
    if enabled.is_some_and(|value| value != "true") {
        return unavailable(
            "not_configured",
            "The Rust Ghidra provider is disabled by REA_GHIDRA_RUST_ENABLED. Unset it or set REA_GHIDRA_RUST_ENABLED=true to enable the provider.",
        );
    }
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return unavailable(
            "unsupported_host",
            "The Rust worker requires macOS or Linux.",
        );
    }
    let invalid = || {
        unavailable(
            "not_configured",
            "Configure absolute REA_GHIDRA_RUST_WORKER and REA_GHIDRA_RUST_CACHE_DIR paths, a positive REA_GHIDRA_RUST_TIMEOUT_MS value, and an optional positive REA_GHIDRA_RUST_MEMORY_MIB threshold.",
        )
    };
    let (command, worker_source) = match setting(environment, "REA_GHIDRA_RUST_WORKER") {
        Some(command) => (command.to_owned(), "environment"),
        None => match default_worker(current_executable) {
            Some(command) => (command, "default"),
            None => {
                return unavailable(
                    "not_configured",
                    format!(
                        "The Rust worker location could not be derived from the rea executable. {BUILD_GUIDANCE}"
                    ),
                );
            }
        },
    };
    let (cache_directory, cache_source) = match setting(environment, "REA_GHIDRA_RUST_CACHE_DIR") {
        Some(directory) => (directory.to_owned(), "environment"),
        None => match default_cache_directory(environment) {
            Some(directory) => (directory, "default"),
            None => return invalid(),
        },
    };
    let (timeout_ms, timeout_source) = match environment.get("REA_GHIDRA_RUST_TIMEOUT_MS") {
        None => (DEFAULT_TIMEOUT_MS, "default"),
        Some(text) => match positive_decimal(text, MAX_TIMEOUT_MS) {
            Some(timeout) => (timeout, "environment"),
            None => return invalid(),
        },
    };
    let memory_mib = match environment.get("REA_GHIDRA_RUST_MEMORY_MIB") {
        None => None,
        Some(text) => match positive_decimal(text, MAX_MEMORY_MIB) {
            Some(memory) => Some(memory),
            None => return invalid(),
        },
    };
    let (decompile_threads, threads_source) =
        match environment.get("REA_GHIDRA_RUST_DECOMPILE_THREADS") {
            None => (default_decompile_threads(memory_mib), "default"),
            Some(text) => match positive_decimal(text, MAX_DECOMPILE_THREADS) {
                Some(threads) => (threads as usize, "environment"),
                None => return invalid(),
            },
        };
    if !absolute(&command) || !absolute(&cache_directory) {
        return invalid();
    }
    if let Err(cause) = executable(Path::new(&command)) {
        let guidance = if worker_source == "default" {
            format!(" {BUILD_GUIDANCE}")
        } else {
            String::new()
        };
        return unavailable(
            "executable_missing",
            format!("Cannot execute the Rust worker: {cause}{guidance}"),
        );
    }
    let configuration = Configuration {
        command,
        cache_directory,
        timeout_ms,
        memory_mib,
        decompile_threads,
        sources: Sources {
            worker: worker_source,
            cache_directory: cache_source,
            timeout_ms: timeout_source,
            decompile_threads: threads_source,
        },
    };
    let mut diagnostics = Map::new();
    diagnostics.insert("command".into(), json!(configuration.command));
    diagnostics.insert(
        "cacheDirectory".into(),
        json!(configuration.cache_directory),
    );
    diagnostics.insert("timeoutMs".into(), json!(configuration.timeout_ms));
    diagnostics.insert(
        "decompile_threads".into(),
        json!(configuration.decompile_threads),
    );
    diagnostics.insert("explicitly_enabled".into(), json!(enabled == Some("true")));
    diagnostics.insert(
        "configuration_sources".into(),
        json!({
            "worker": configuration.sources.worker,
            "cache_directory": configuration.sources.cache_directory,
            "timeout_ms": configuration.sources.timeout_ms,
            "decompile_threads": configuration.sources.decompile_threads,
        }),
    );
    for (key, value) in memory_policy(memory_mib) {
        diagnostics.insert(key, value);
    }
    diagnostics.insert(
        "memory_monitor_state".into(),
        json!(if memory_mib.is_none() {
            "disabled"
        } else {
            "not_probed"
        }),
    );
    Inspection::Available {
        configuration,
        diagnostics,
    }
}

/// Available parallelism up to the default ceiling, reduced so the expected
/// Program memory stays inside a configured worker RSS threshold.
fn default_decompile_threads(memory_mib: Option<u64>) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    let threads = cores.min(DEFAULT_MAX_DECOMPILE_THREADS);
    match memory_mib {
        Some(memory) => threads.min(
            usize::try_from(memory / PROGRAM_MEMORY_MIB)
                .unwrap_or(usize::MAX)
                .max(1),
        ),
        None => threads,
    }
}

/// `accessSync(command, X_OK)` plus the regular-file check.
fn executable(path: &Path) -> Result<(), String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("Error: {error}, access '{}'", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!(
                "Error: permission denied, access '{}'",
                path.display()
            ));
        }
    }
    if !metadata.is_file() {
        return Err("Error: The configured worker is not a regular file.".into());
    }
    Ok(())
}

/// `ghidraRustWorkerEnvironment`: pass worker controls explicitly; REA owns
/// the optional RSS supervision, so the worker never sees the memory setting.
pub(crate) fn worker_environment(
    environment: &HashMap<String, String>,
    configuration: &Configuration,
) -> Vec<(OsString, OsString)> {
    let mut worker = environment.clone();
    worker.insert(
        "REA_GHIDRA_RUST_CACHE_DIR".into(),
        configuration.cache_directory.clone(),
    );
    worker.insert(
        "REA_GHIDRA_RUST_TIMEOUT_MS".into(),
        configuration.timeout_ms.to_string(),
    );
    // The worker validates its own invocation; defaults are made explicit.
    worker.insert("REA_GHIDRA_RUST_ENABLED".into(), "true".into());
    worker.insert(
        "REA_GHIDRA_RUST_WORKER".into(),
        configuration.command.clone(),
    );
    worker.remove("REA_GHIDRA_RUST_MEMORY_MIB");
    worker.insert(
        "REA_GHIDRA_RUST_DECOMPILE_THREADS".into(),
        configuration.decompile_threads.to_string(),
    );
    if cfg!(target_os = "macos") {
        worker.insert("MallocSpaceEfficient".into(), "1".into());
    }
    let mut pairs = worker
        .into_iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
}
