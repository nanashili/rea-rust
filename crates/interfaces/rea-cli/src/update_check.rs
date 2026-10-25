//! Detached, read-only update refresh used by Incur's hidden flag.
//!
//! The normal CLI never prints this result. Incur starts a separate process
//! with `--incur-update-check`; this process refreshes the same cache record
//! that the TypeScript launcher reads and then exits quietly.

use rea_application::maintenance_update::run_update_check;
use rea_application::package_identity::discover_current_package_root;
use rea_core::cancellation::Cancellation;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const PACKAGE_CACHE_KEY: &str = "rea-agents";

/// Run the detached refresh. Every failure is intentionally silent: this is a
/// best-effort background operation and its parent process has already served
/// the cached notification, if any.
pub(crate) fn run() -> i32 {
    let environment = std::env::vars().collect::<BTreeMap<_, _>>();
    #[cfg(unix)]
    let interrupts = match rea_host::command_interrupts::CommandInterrupts::install() {
        Ok(interrupts) => Some(interrupts),
        Err(_) => return 0,
    };
    #[cfg(unix)]
    let cancellation = interrupts
        .as_ref()
        .map(|value| value.cancellation().clone())
        .unwrap_or_default();
    #[cfg(not(unix))]
    let cancellation = Cancellation::default();
    let status = run_refresh(&environment, &cancellation);

    #[cfg(unix)]
    if let Some(interrupts) = interrupts {
        if let Some(signal_exit) = interrupts.finish() {
            return signal_exit as i32;
        }
    }

    status
}

fn run_refresh(environment: &BTreeMap<String, String>, cancellation: &Cancellation) -> i32 {
    let Ok(identity) = discover_current_package_root() else {
        return 0;
    };
    let result = run_update_check(
        &identity.version,
        &identity.package_root,
        environment,
        cancellation,
    );

    if cancellation.reason().is_some() {
        return 0;
    }

    let Some(latest) = latest_version(&result) else {
        return 0;
    };
    let Some(cache_path) = cache_path(environment) else {
        return 0;
    };

    let checked_at = unix_time_millis();
    let cache = serde_json::json!({
        "checkedAt": checked_at,
        "latest": latest,
    });
    if write_cache_atomically(&cache_path, &cache).is_err() {
        return 0;
    }
    0
}

fn latest_version(result: &Value) -> Option<&str> {
    match result.get("status").and_then(Value::as_str) {
        Some("current") | Some("available") => result.get("latestVersion").and_then(Value::as_str),
        _ => None,
    }
}

fn cache_path(environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    let root = environment
        .get("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty())
        .cloned()
        .or_else(|| {
            environment
                .get("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| format!("{home}/.cache"))
        })?;
    Some(
        PathBuf::from(root)
            .join("incur")
            .join("updates")
            .join(format!("{PACKAGE_CACHE_KEY}.json")),
    )
}

fn unix_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn write_cache_atomically(path: &Path, value: &Value) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "cache path has no parent")
    })?;
    fs::create_dir_all(parent)?;
    reject_symlink(path)?;

    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let serialized = match serde_json::to_vec(value) {
        Ok(serialized) => serialized,
        Err(error) => {
            return Err(cleanup_after_failure(
                &temporary,
                std::io::Error::other(error.to_string()),
            ));
        }
    };
    if let Err(error) = file.write_all(&serialized) {
        return Err(cleanup_after_failure(&temporary, error));
    }
    if let Err(error) = file.write_all(b"\n") {
        return Err(cleanup_after_failure(&temporary, error));
    }
    if let Err(error) = file.sync_all() {
        return Err(cleanup_after_failure(&temporary, error));
    }
    drop(file);

    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => Err(cleanup_after_failure(&temporary, error)),
    }
}

fn cleanup_after_failure(path: &Path, primary: std::io::Error) -> std::io::Error {
    match fs::remove_file(path) {
        Ok(()) => primary,
        Err(cleanup) => std::io::Error::other(format!(
            "{primary}; temporary cache cleanup failed: {cleanup}"
        )),
    }
}

fn reject_symlink(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to replace a symlinked update cache",
        )),
        Ok(metadata) if !metadata.is_file() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "update cache is not a regular file",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let process = std::process::id();
    let nonce = unix_time_millis();
    path.with_extension(format!("json.{process}.{nonce}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn writes_incur_compatible_cache_record() {
        let directory = TempDir::new().expect("temporary cache directory");
        let path = directory.path().join("incur/updates/rea-agents.json");
        write_cache_atomically(
            &path,
            &serde_json::json!({"checkedAt": 12, "latest": "2.0.0"}),
        )
        .expect("cache should be written");
        let value: Value = serde_json::from_slice(&fs::read(path).expect("cache should be read"))
            .expect("cache should be valid JSON");
        assert_eq!(value["checkedAt"], 12);
        assert_eq!(value["latest"], "2.0.0");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_cache() {
        use std::os::unix::fs::symlink;
        let directory = TempDir::new().expect("temporary cache directory");
        let path = directory.path().join("cache.json");
        let target = directory.path().join("target.json");
        fs::write(&target, "original").expect("target should be written");
        symlink(&target, &path).expect("symlink should be created");
        assert!(write_cache_atomically(&path, &serde_json::json!({})).is_err());
        assert_eq!(
            fs::read_to_string(target).expect("target should remain"),
            "original"
        );
    }
}
