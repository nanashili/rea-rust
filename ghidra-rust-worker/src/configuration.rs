use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::metadata;

pub struct Configuration {
    pub cache_directory: PathBuf,
    pub timeout_ms: u64,
    pub worker_sha256: String,
    pub identity: String,
    /// Decompiler Programs used in parallel; each holds a full Program.
    pub decompile_threads: usize,
}

impl Configuration {
    pub fn load() -> Result<Self> {
        validate_invocation()?;
        let executable = configured_executable()?;
        let cache_directory = absolute_environment_path("REA_GHIDRA_RUST_CACHE_DIR")?;
        let timeout_ms = configured_timeout()?;
        let worker_sha256 = hash_file(&executable)?;
        let identity = hash_bytes(&serde_json::to_vec(&json!({
            "engine": metadata::engine(),
            "worker_sha256": worker_sha256
        }))?);

        create_cache_directory(&cache_directory)?;
        let decompile_threads = configured_threads()?;

        Ok(Self {
            cache_directory,
            timeout_ms,
            worker_sha256,
            identity,
            decompile_threads,
        })
    }

    pub fn cache_path(&self, target_sha256: &str) -> PathBuf {
        let key = hash_bytes(format!("{}:{target_sha256}", self.identity).as_bytes());
        self.cache_directory.join(format!("{key}.redb"))
    }
}

fn create_cache_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).context("Create cache directory")?;
    persist_cache_directory_chain(path)
}

#[cfg(unix)]
fn persist_cache_directory_chain(path: &Path) -> Result<()> {
    for directory in path.ancestors() {
        std::fs::File::open(directory)
            .with_context(|| format!("Open cache directory ancestor: {}", directory.display()))?
            .sync_all()
            .with_context(|| {
                format!("Persist cache directory ancestor: {}", directory.display())
            })?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn persist_cache_directory_chain(_path: &Path) -> Result<()> {
    // Rust's standard library has no portable directory fsync on these platforms.
    Ok(())
}

fn validate_invocation() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    ensure!(
        arguments.next().as_deref() == Some(std::ffi::OsStr::new("--rea-rust-ghidra-worker"))
            && arguments.next().is_none(),
        "Expected only --rea-rust-ghidra-worker"
    );
    ensure!(
        std::env::var("REA_GHIDRA_RUST_ENABLED").as_deref() == Ok("true"),
        "REA_GHIDRA_RUST_ENABLED=true is required to opt in"
    );
    ensure!(
        std::env::var_os("REA_GHIDRA_RUST_MEMORY_MIB").is_none(),
        "This worker does not enforce a process memory limit"
    );
    Ok(())
}

fn configured_executable() -> Result<PathBuf> {
    let configured = absolute_environment_path("REA_GHIDRA_RUST_WORKER")?;
    let executable = std::env::current_exe().context("Resolve the running worker")?;
    ensure!(
        configured
            .canonicalize()
            .context("Resolve the configured worker")?
            == executable
                .canonicalize()
                .context("Resolve the running worker path")?,
        "Configured worker path does not identify this executable"
    );
    Ok(executable)
}

fn absolute_environment_path(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("{name} is required"))?;
    ensure!(path.is_absolute(), "{name} must be absolute");
    Ok(path)
}

fn configured_timeout() -> Result<u64> {
    let timeout_ms = std::env::var("REA_GHIDRA_RUST_TIMEOUT_MS")
        .context("REA_GHIDRA_RUST_TIMEOUT_MS is required")?
        .parse::<u64>()
        .context("Invalid request timeout")?;
    ensure!(
        (1..=2_147_483_647).contains(&timeout_ms),
        "Invalid request timeout"
    );
    Ok(timeout_ms)
}

/// `REA_GHIDRA_RUST_DECOMPILE_THREADS`, chosen by the host. Absent means one
/// Program, the previous sequential behavior.
fn configured_threads() -> Result<usize> {
    let Some(value) = std::env::var_os("REA_GHIDRA_RUST_DECOMPILE_THREADS") else {
        return Ok(1);
    };
    let threads = value
        .to_str()
        .and_then(|text| text.parse::<usize>().ok())
        .context("Invalid decompile thread count")?;
    ensure!(
        (1..=crate::decompiler_pool::MAX_DECOMPILE_THREADS).contains(&threads),
        "Invalid decompile thread count"
    );
    Ok(threads)
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::with_capacity(64 * 1024, File::open(path)?);
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hash.finalize()))
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn validate_digest(text: &str) -> Result<()> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("Expected a lowercase SHA-256 digest");
    }
    Ok(())
}
